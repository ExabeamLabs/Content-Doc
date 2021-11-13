#### Parser Content
```Java
{
Name = symantec-usb-insert-1
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Splunk
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "Device Manager Message", "Allowed the device", "User: " ]
  Fields = [
    """exabeam_host=({host}[^,\s]{1,2000})""",
    """SymantecServer:\s{0,100}({host}[\w\-.]{1,2000})""",
    """(\s|,)({dest_host}[^,\s]{1,2000}),Device Manager Message""",
    """,Local: (0\.0\.0\.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """Begin:\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """User:\s{1,100}({user}.+?),Domain""",
    """({activity}Allowed the device)""",
    """Domain:\s{1,100}({domain}[^,]{1,2000}),""",
    """\[class\]:(?:\?|({device_type}.+?))\s{1,100}\[guid\]:""",
    """Device ID:\s{1,100}({device_id}.+)&\d{1,100}""",
    """\[deviceID\]:({device_id}.+)&\d{1,100}""",
    """Allowed the device\.\s{1,100}({activity_details}.*?)\s{1,100}\[guid"""
  ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "activity_details->description"]
    NameTemplate = """Symantec ${device_type} insert found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="dest_address", Fields=["dest_host->host_name", "dest_ip->ip_address"]

}
```