#### Parser Content
```Java
{
Name = beyondtrust-privileged-access
  Vendor = BeyondTrust
  Product = BeyondTrust PowerBroker
  Lms = Direct
  DataType = "privileged-access"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [  """|BeyondTrust|""","""Application Requested Elevation""","""BeyondTrustBeyondInsightEventTypeID=28691""" ]
  Fields = [
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) CEF""",
    """\|rt=({time}\w+ \d+ \d{4} \d\d:\d\d:\d\d)""",
    """BeyondTrustBeyondInsightUserName=(?: |({user}.+?)\s+\w+=)""",
    """BeyondTrustBeyondInsightPath=(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?))\s+\w+=)""",
    """BeyondTrustBeyondInsightAssetName=(?: |({dest_host}.+?)\s+\w+=)""",
    """BeyondTrustBeyondInsightUserType=(?: |({privileges}.+?)\s*$)""",
    """deviceExternalId=({event_code}pbw|pbmac)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```