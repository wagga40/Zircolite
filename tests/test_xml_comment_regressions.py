"""Valid XML annotations must not discard records or event fields."""

import pytest
from lxml import etree

from zircolite.config import ExtractorConfig
from zircolite.extractor import EvtxExtractor
from zircolite.streaming import StreamingEventProcessor

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
ANNOTATIONS = ["<!-- exported event -->", "<?export source?>"]
POSITIONS = [
    "/Event",
    "/Event/System",
    "/Event/System/EventID",
    "/Event/System/Provider",
    "/Event/EventData",
    "/Event/UserData",
    "/Event/UserData/Payload",
]
EVENT_XML = """<Event>
    <System><EventID>1</EventID><Provider Name="Example"/></System>
    <EventData><Data Name="CommandLine">example.exe</Data></EventData>
    <UserData><Payload><SubjectUserName>alice</SubjectUserName></Payload></UserData>
</Event>"""


@pytest.mark.parametrize("annotation", ANNOTATIONS, ids=["comment", "instruction"])
@pytest.mark.parametrize("position", POSITIONS)
def test_xml_annotations_preserve_event_fields(annotation, position):
    root = etree.fromstring(EVENT_XML)
    parent = root.xpath(position)[0]
    parent.append(etree.fromstring(f"<wrapper>{annotation}</wrapper>")[0])

    event = EvtxExtractor().xml_to_dict(root)

    assert event == {
        "Event": {
            "#attributes": {"xmlns": EVENT_NS},
            "System": {"EventID": 1, "Provider": {"#attributes": {"Name": "Example"}}},
            "EventData": {"CommandLine": "example.exe"},
            "UserData": {"SubjectUserName": "alice"},
        }
    }


@pytest.mark.parametrize("annotation", ANNOTATIONS, ids=["comment", "instruction"])
@pytest.mark.parametrize("split", [0, 1], ids=["before-text", "within-text"])
@pytest.mark.parametrize(
    ("field_xml", "value", "expected"),
    [
        (
            "<System><EventID>{text}</EventID></System>",
            "4688",
            {"System": {"EventID": 4688}},
        ),
        (
            '<System><EventID Qualifiers="0">{text}</EventID></System>',
            "4688",
            {"System": {"EventID": {"#attributes": {"Qualifiers": "0"}, "#text": 4688}}},
        ),
        (
            "<System><Qualifiers>{text}</Qualifiers></System>",
            "0016",
            {"System": {"Qualifiers": "0016"}},
        ),
        (
            '<EventData><Data Name="Image">{text}</Data></EventData>',
            "cmd.exe",
            {"EventData": {"Image": "cmd.exe"}},
        ),
        (
            "<EventData><Data>{text}</Data></EventData>",
            "0016",
            {"EventData": {"Data": ["0016"]}},
        ),
        (
            "<EventData><Image>{text}</Image></EventData>",
            "cmd.exe",
            {"EventData": {"Image": "cmd.exe"}},
        ),
        (
            "<UserData><Payload><SubjectUserName>{text}</SubjectUserName></Payload></UserData>",
            "alice",
            {"UserData": {"SubjectUserName": "alice"}},
        ),
    ],
    ids=["event-id", "event-id-attributes", "qualifiers", "named-data", "unnamed-data", "field", "userdata"],
)
def test_xml_annotations_preserve_complete_leaf_text(annotation, split, field_xml, value, expected):
    text = value[:split] + annotation + value[split:]
    root = etree.fromstring("<Event>" + field_xml.format(text=text) + "</Event>")

    event = EvtxExtractor().xml_to_dict(root)

    assert event == {"Event": {"#attributes": {"xmlns": EVENT_NS}, **expected}}


@pytest.mark.parametrize("namespace", ["", f' xmlns="{EVENT_NS}"'])
def test_streaming_keeps_annotated_events_without_degraded_ingestion(
    tmp_path, field_mappings_file, default_args_config, test_logger, namespace
):
    source = tmp_path / "annotated.xml"
    source.write_text(
        f"""<Events><Event{namespace}>
            <!-- event annotation --><?event source?>
            <System><!-- system annotation --><?system source?>
                <EventID>4<!-- split event id -->688</EventID>
            </System>
            <EventData><!-- data annotation --><?data source?>
                <Data Name="CommandLine"><!-- before text -->example<?split text?>.exe</Data>
            </EventData>
            <UserData><!-- user data annotation --><?userdata source?>
                <Payload><!-- payload annotation --><?payload source?>
                    <SubjectUserName><?before text?>al<!-- split name -->ice</SubjectUserName>
                </Payload>
            </UserData>
        </Event><Event{namespace}><System><EventID>2</EventID></System></Event></Events>""",
        encoding="utf-8",
    )
    processor = StreamingEventProcessor(
        config_file=field_mappings_file,
        args_config=default_args_config,
        logger=test_logger,
    )
    extractor = EvtxExtractor(ExtractorConfig(xml_logs=True), logger=test_logger)

    events = list(processor.stream_xml_events(str(source), extractor))

    assert [event["EventID"] for event in events] == [4688, 2]
    assert events[0]["CommandLine"] == "example.exe"
    assert events[0]["SubjectUserName"] == "alice"
    assert not processor.ingest_degraded
