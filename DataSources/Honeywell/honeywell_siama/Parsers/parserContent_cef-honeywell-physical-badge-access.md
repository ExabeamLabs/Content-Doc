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
    """\Wrt=({time}\d+)""",
    """\Wahost=({host}[\w\-.]+)""",
    """\Wsuser=({last_name}[^,=]+),\s*({first_name}[^,=]+?)\s+(\w+=|$)""",
    """\Wduser=({user}.+?)\s+(\w+=|$)""",
    """\Wsuid=({user_id}[^\s]+)""",
    """\Wmsg=({location_door}.+?)\s+(\w+=|$)""",
    """\Wcn2=({src_location_id}.+?)\s+(\w+=|$)""",
    """\Wcn3=({location_door_id}.+?)\s+(\w+=|$)""",
    """\Wcn1=({door_side_id}.+?)\s+(\w+=|$)""",
    """CEF:([^\|]*\|){5}({event_name}[^\|]+)""",
  ]
    DupFields = ["user_id->badge_id"]
}
```