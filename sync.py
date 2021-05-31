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
import logging
import logging.handlers
import os
import sys
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
            cfg["trello"]["access_token"],
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


def get_expected_events(cfg: Config):
    expected_events: List[Event] = []
    lists_by_id = get_lists_by_id(cfg)
    for card in get_cards(cfg):
        # No time data - can't map to a calendar
        if not card["due"]:
            continue

        if card["desc"]:
            description = f'{card["desc"]}\\n\\nCard URL: {card["url"]}'
        else:
            description = f'Card URL: {card["url"]}'

        if card["start"]:
            start_date = datetime.strptime(
                card["start"], "%Y-%m-%dT%H:%M:%S.%f%z"
            ).replace(hour=0, minute=0, second=0, microsecond=0)
            due_date = datetime.strptime(card["due"], "%Y-%m-%dT%H:%M:%S.%f%z")
        else:
            due_date = datetime.strptime(card["due"], "%Y-%m-%dT%H:%M:%S.%f%z")
            start_date = due_date - timedelta(hours=1)

        expected_events.append(
            Event(
                sha256(f'{card["id"]}xxx@trello.com'.encode("utf-8")).hexdigest(),
                f'{card["name"]} [{lists_by_id[card["idList"]]["name"]}]',
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
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "credentials.json"),
                ["https://www.googleapis.com/auth/calendar.events"],
            )
            creds = flow.run_local_server(port=0)

        with open(token_path, "w") as token:
            token.write(creds.to_json())

    return creds


def get_current_events(cfg: Config):
    service = build(
        "calendar", "v3", credentials=cfg.google_credentials, cache_discovery=False
    )
    events = service.events().list(calendarId=cfg.google_calendar_id).execute()
    return [
        Event(
            event["id"],
            event["summary"],
            event["description"],
            datetime.fromisoformat(event["start"]["dateTime"]),
            datetime.fromisoformat(event["end"]["dateTime"]),
        )
        for event in events["items"]
    ]


def create_event(cfg: Config, event: Event):
    build(
        "calendar", "v3", credentials=cfg.google_credentials, cache_discovery=False
    ).events().insert(
        calendarId=cfg.google_calendar_id,
        body={
            "summary": event.name,
            "description": event.description,
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
    ).execute()


def remove_event(cfg: Config, event: Event):
    build(
        "calendar", "v3", credentials=cfg.google_credentials, cache_discovery=False
    ).events().delete(
        calendarId=cfg.google_calendar_id,
        eventId=event.id,
    ).execute()


def update_event(cfg: Config, event: Event):
    build(
        "calendar", "v3", credentials=cfg.google_credentials, cache_discovery=False
    ).events().update(
        calendarId=cfg.google_calendar_id,
        eventId=event.id,
        body={
            "summary": event.name,
            "description": event.description,
            "start": {
                "dateTime": event.start_date.astimezone(timezone.utc).isoformat(),
                "timeZone": "UTC",
            },
            "end": {
                "dateTime": event.end_date.astimezone(timezone.utc).isoformat(),
                "timeZone": "UTC",
            },
        },
    ).execute()


def main():
    cfg = Config.from_file(PosixPath(os.environ.get("TRELLO_ICS_CFG", "trello-gcal-syncer.cfg")))

    expected_events = get_expected_events(cfg)
    current_events = get_current_events(cfg)
    logger.info(
        f"Found {len(expected_events)} expected events, {len(current_events)} current events"
    )

    expected_event_ids = [e.id for e in expected_events]
    current_event_ids = [e.id for e in current_events]

    events_to_add = [
        event
        for event in expected_events
        if event not in current_events and event.id not in current_event_ids
    ]
    events_to_remove = [
        event
        for event in current_events
        if event not in expected_events and event.id not in expected_event_ids
    ]
    events_to_update = [
        event
        for event in expected_events
        if event not in current_events and event.id in current_event_ids
    ]

    for event in events_to_add:
        logger.info(f"Creating event: {event}")
        create_event(cfg, event)

    for event in events_to_remove:
        logger.info(f"Removing event: {event}")
        remove_event(cfg, event)

    for event in events_to_update:
        logger.info(f"Updating event: {event}")
        update_event(cfg, event)


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    if PosixPath('/dev/log').exists():
        logger.addHandler(logging.handlers.SysLogHandler('/dev/log'))

    main()
