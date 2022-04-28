#!/usr/bin/env python3
"""
Trello to Google calendar syncer

Simple script to sync Trello cards to Google calendar entries.

MIT License

Copyright (c) 2021 Infra Bits

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import configparser
import logging.handlers
import os
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from pathlib import PosixPath
from typing import List

import requests
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Event:
    id: str
    name: str
    description: str
    start_date: datetime
    end_date: datetime


@dataclass(frozen=True)
class Config:
    trello_access_key: str
    trello_access_token: str
    trello_board_id: str
    google_calendar_id: str
    google_credentials: Credentials

    @staticmethod
    def from_file(path: PosixPath):
        cfg = configparser.ConfigParser()
        cfg.read(path.as_posix())

        return Config(
            cfg["trello"]["access_key"],
            cfg["trello"].get("access_token"),
            cfg["trello"]["board_id"],
            cfg["google"]["calendar_id"],
            get_google_creds(),
        )


def get_cards(cfg: Config):
    r = requests.get(
        f"https://api.trello.com/1/boards/{cfg.trello_board_id}/cards/visible",
        params={
            "key": cfg.trello_access_key,
            "token": cfg.trello_access_token,
        },
    )
    r.raise_for_status()
    return r.json()


def get_lists_by_id(cfg: Config):
    r = requests.get(
        f"https://api.trello.com/1/boards/{cfg.trello_board_id}/lists",
        params={
            "key": cfg.trello_access_key,
            "token": cfg.trello_access_token,
        },
    )
    r.raise_for_status()
    return {list["id"]: list for list in r.json()}


def get_checklists_by_id(cfg: Config):
    r = requests.get(
        f"https://api.trello.com/1/boards/{cfg.trello_board_id}/checklists",
        params={
            "key": cfg.trello_access_key,
            "token": cfg.trello_access_token,
        },
    )
    r.raise_for_status()
    return {clist["id"]: clist for clist in r.json()}


def update_card_position(cfg: Config, card_id: int, position: int):
    r = requests.put(
        f"https://api.trello.com/1/cards/{card_id}",
        params={
            "key": cfg.trello_access_key,
            "token": cfg.trello_access_token,
            "pos": position,
        },
    )
    r.raise_for_status()
    return r.json()


def get_expected_events(cfg: Config):
    expected_events: List[Event] = []
    lists_by_id = get_lists_by_id(cfg)
    checklists_by_id = get_checklists_by_id(cfg)

    for card in get_cards(cfg):
        # No time data - can't map to a calendar
        if not card["due"]:
            continue

        checklist_items = []
        if card["idChecklists"]:
            for clist in card["idChecklists"]:
                for clitem in checklists_by_id[clist]['checkItems']:
                    checklist_items.append(f'[{"X" if clitem["state"] == "complete" else " "}]'
                                           f' {clitem["name"]}')

        description = ''
        if card["desc"]:
            description += f'{card["desc"]}\\n\\n'

            if checklist_items:
                description += '---------------------------\\n'

        if checklist_items:
            description += '\n'.join(checklist_items)
            description += '\n\n'

        description += f'Card URL: {card["url"]}'

        if card["start"]:
            start_date = datetime.strptime(
                card["start"], "%Y-%m-%dT%H:%M:%S.%f%z"
            ).astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            due_date = datetime.strptime(card["due"], "%Y-%m-%dT%H:%M:%S.%f%z")
        else:
            due_date = datetime.strptime(card["due"], "%Y-%m-%dT%H:%M:%S.%f%z")
            start_date = due_date - timedelta(hours=1)

        summary = f'{card["name"]} [{lists_by_id[card["idList"]]["name"]}]'
        if card.get("dueComplete"):
            summary = "".join([f'\u0336{c}' for c in summary])

        expected_events.append(
            Event(
                sha256(f'{card["id"]}@trello.com'.encode("utf-8")).hexdigest(),
                summary,
                description,
                start_date,
                due_date,
            )
        )
    return expected_events


def get_google_creds():
    creds = None
    token_path = os.environ.get("GOOGLE_APPLICATION_TOKEN", "token.json")

    if PosixPath(token_path).exists():
        creds = Credentials.from_authorized_user_file(
            token_path, ["https://www.googleapis.com/auth/calendar.events"]
        )

    if creds:
        creds.refresh(Request())

    if not creds:
        flow = InstalledAppFlow.from_client_secrets_file(
            os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "credentials.json"),
            ["https://www.googleapis.com/auth/calendar.events"],
        )
        creds = flow.run_local_server(port=0)

    with open(token_path, "w") as token:
        token.write(creds.to_json())

    return creds


def get_current_events(cfg: Config):
    service = build("calendar", "v3", credentials=cfg.google_credentials, cache_discovery=False)
    events = service.events().list(calendarId=cfg.google_calendar_id, showDeleted=True).execute()

    active_events, deleted_events = [], []

    for event in events["items"]:
        e = Event(
            event["id"],
            event["summary"],
            event["description"],
            datetime.fromisoformat(event["start"]["dateTime"]),
            datetime.fromisoformat(event["end"]["dateTime"]),
        )
        if event["status"] == "cancelled":
            deleted_events.append(e)
        else:
            active_events.append(e)
    return active_events, deleted_events


def create_events(cfg: Config, events: List[Event]):
    if not events:
        return
    logger.info(f"Creating {len(events)} events: {', '.join([e.id for e in events])}")

    service = build("calendar", "v3", credentials=cfg.google_credentials, cache_discovery=False)
    batch = service.new_batch_http_request()
    for event in events:
        batch.add(
            service.events().insert(
                calendarId=cfg.google_calendar_id,
                body={
                    "summary": event.name,
                    "description": event.description,
                    "status": "confirmed",
                    "id": event.id,
                    "start": {
                        "dateTime": event.start_date.astimezone(timezone.utc).isoformat(),
                        "timeZone": "UTC",
                    },
                    "end": {
                        "dateTime": event.end_date.astimezone(timezone.utc).isoformat(),
                        "timeZone": "UTC",
                    },
                },
            ),
            callback=lambda id, resp, ex: logger.info(f'Created {event.id}: [{id}] {resp} / {ex}')
        )
    batch.execute()


def remove_events(cfg: Config, events: List[Event]):
    if not events:
        return
    logger.info(f"Removing {len(events)} events: {', '.join([e.id for e in events])}")

    service = build("calendar", "v3", credentials=cfg.google_credentials, cache_discovery=False)
    batch = service.new_batch_http_request()
    for event in events:
        batch.add(
            service.events().delete(calendarId=cfg.google_calendar_id, eventId=event.id),
            callback=lambda id, resp, ex: logger.info(f'Removed {event.id}: [{id}] {resp} / {ex}')
        )
    batch.execute()


def update_events(cfg: Config, events: List[Event]):
    if not events:
        return
    logger.info(f"Updating {len(events)} events: {', '.join([e.id for e in events])}")

    service = build("calendar", "v3", credentials=cfg.google_credentials, cache_discovery=False)
    batch = service.new_batch_http_request()
    for event in events:
        batch.add(
            service.events().update(
                calendarId=cfg.google_calendar_id,
                eventId=event.id,
                body={
                    "summary": event.name,
                    "description": event.description,
                    "status": "confirmed",
                    "start": {
                        "dateTime": event.start_date.astimezone(timezone.utc).isoformat(),
                        "timeZone": "UTC",
                    },
                    "end": {
                        "dateTime": event.end_date.astimezone(timezone.utc).isoformat(),
                        "timeZone": "UTC",
                    },
                },
            ),
            callback=lambda id, resp, ex: logger.info(f'Updated {event.id}: [{id}] {resp} / {ex}')
        )
    batch.execute()


def sync_events(cfg: Config):
    expected_events = get_expected_events(cfg)
    active_events, deleted_events = get_current_events(cfg)

    logger.info(f"Found {len(expected_events)} expected events, "
                f"{len(active_events)} active events, "
                f"{len(deleted_events)} deleted events")

    # Events are just objects with a unique ID
    # Thus we can only have 1 entry for each task ever =\
    expected_event_ids = [e.id for e in expected_events]
    known_event_ids = [e.id for e in active_events + deleted_events]

    create_events(cfg, [
        event
        for event in expected_events
        if event not in active_events and event.id not in known_event_ids
    ])

    remove_events(cfg, [
        event
        for event in active_events
        if event not in expected_events and event.id not in expected_event_ids
    ])

    update_events(cfg, [
        event
        for event in expected_events
        if event not in active_events and event.id in known_event_ids
    ])


def sort_cards(cfg: Config):
    cards_by_list = defaultdict(list)

    lists_by_id = get_lists_by_id(cfg)
    for card in get_cards(cfg):
        cards_by_list[card["idList"]].append(card)

    for listId, cards in cards_by_list.items():
        logger.info(f'Sorting cards in {lists_by_id[listId]["name"]}')
        sorted_cards = sorted(
            cards,
            key=lambda c: [
                (
                    datetime.strptime(c["due"], "%Y-%m-%dT%H:%M:%S.%f%z")
                    if c["due"] else
                    (
                        datetime.utcnow() + timedelta(days=1825)
                    ).astimezone(timezone.utc)
                ),
                c["name"],
                c["id"]
            ]
        )

        # Don't re-order lists that don't contain cards with due dates
        if not [c for c in sorted_cards if c["due"]]:
            continue

        # The position does not appear to be literally stored & thus is not returned the same
        # So re-order every card if our overall order does not match what we expect :(
        if [c["id"] for c in sorted_cards] != [c["id"] for c in cards]:
            for x, card in enumerate(sorted_cards):
                logger.info(f"Moving card {card['id']} to position {x} from {card['pos']}")
                update_card_position(cfg, card["id"], x+1)


def main():
    cfg = Config.from_file(PosixPath(os.environ.get("TRELLO_ICS_CFG", "trello-gcal-syncer.cfg")))

    if not cfg.trello_access_token:
        import urllib.parse
        params = urllib.parse.urlencode({
            "key": cfg.trello_access_key,
            "response_type": "token",
            "scope": "read,write",
            "expiration": "never",
            "name": "Trello -> Google Calendar syncer",
        })

        logger.info(f'Visit https://api.trello.com/1/authorize?{params} & configure the token')
        return

    sync_events(cfg)
    sort_cards(cfg)


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    if PosixPath('/dev/log').exists():
        logger.addHandler(logging.handlers.SysLogHandler('/dev/log'))

    main()
