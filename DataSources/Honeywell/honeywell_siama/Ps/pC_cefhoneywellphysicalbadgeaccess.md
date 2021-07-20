#### Parser Content
```Java
{
Name = cef-honeywell-physical-badge-access
  Vendor = Honeywell
  Product = honeywell siama
  Lms = Splunk
  DataType = "physical-access"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|SKUD|SKUD|""", """|SKUD """, """externalId=""", """eventId=""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wahost=({host}[\w\-.]{1,2000})""",
    """\Wsuser=({last_name}[^,=]{1,2000}),\s{0,100}({first_name}[^,=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wduser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\Wsuid=({user_id}[^\s]{1,2000})""",
    """\Wmsg=({location_door}.+?)\s{1,100}(\w+=|$)""",
    """\Wcn2=({src_location_id}.+?)\s{1,100}(\w+=|$)""",
    """\Wcn3=({location_door_id}.+?)\s{1,100}(\w+=|$)""",
    """\Wcn1=({door_side_id}.+?)\s{1,100}(\w+=|$)""",
    """CEF:([^\|]{0,2000}\|){5}({event_name}[^\|]{1,2000})""",
  ]
    DupFields = ["user_id->badge_id"]
}
```