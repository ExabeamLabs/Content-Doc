#### Parser Content
```Java
{
Name = symantec-usb-insert
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Splunk
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "Device Manager Message", "device was", "successfully", "User: " ]
  Fields = [
    """exabeam_host=({host}[^,\s]+)""",
    """(\s|,)({dest_host}[^,\s]+),Device Manager Message""",
    """,Local: (0\.0\.0\.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """Begin:\s+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """User:\s+({user}.+?),Domain""",
    """(?i)({activity}device was allowed successfully)""",
    """Domain:\s+({domain}[^,]+),""",
    """\[class\]:(?:\?|({device_type}.+?))\s+\[guid\]:""",
    """Device ID:\s+({device_id}.+)&\d+""",
    """\[deviceID\]:({device_id}.+)&\d+""",
    """The device was allowed successfully\.\s+({activity_details}.*?)\s+\[guid""",
    """The device was Allowed successfully\.\s+({activity_details}[^,]+?),"""
  ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "activity_details->description"]
    NameTemplate = """Symantec ${device_type} insert found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_host->host_name", "dest_ip->ip_address"]}
```