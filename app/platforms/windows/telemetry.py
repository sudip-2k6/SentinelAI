from xml.etree import ElementTree


def events() -> tuple[list[tuple[str, str, str]], str]:
    import pywintypes
    import win32evtlog

    namespace = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    records = []
    try:
        query = win32evtlog.EvtQuery(
            "System",
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
            "*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]",
        )
        result = win32evtlog.EvtNext(query, 32, 5000, 0)
        for handle in result:
            xml = win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
            if len(xml) > 128 * 1024:
                continue
            try:
                system = ElementTree.fromstring(xml).find(namespace + "System")
                if system is None:
                    continue
                provider = system.find(namespace + "Provider")
                created = system.find(namespace + "TimeCreated")
                event_id = system.findtext(namespace + "EventID", "")
                records.append(
                    (
                        created.get("SystemTime", "") if created is not None else "",
                        (provider.get("Name", "") if provider is not None else "")[:160],
                        f"Event {event_id[:20]}",
                    )
                )
            except ElementTree.ParseError:
                continue
    except pywintypes.error as exc:
        return [], f"Windows System log metadata unavailable · {exc}"
    return records, "Windows System log metadata · Last 24 hours"
