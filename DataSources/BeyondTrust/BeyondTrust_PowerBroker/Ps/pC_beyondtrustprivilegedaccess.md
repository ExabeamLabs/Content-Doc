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
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) CEF""",
    """\|rt=({time}\w+ \d{1,100} \d{4} \d\d:\d\d:\d\d)""",
    """BeyondTrustBeyondInsightUserName=(?: |({user}.+?)\s{1,100}\w+=)""",
    """BeyondTrustBeyondInsightPath=(?: |({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}?))\s{1,100}\w+=)""",
    """BeyondTrustBeyondInsightAssetName=(?: |({dest_host}.+?)\s{1,100}\w+=)""",
    """BeyondTrustBeyondInsightUserType=(?: |({privileges}.+?)\s{0,100}$)""",
    """deviceExternalId=({event_code}pbw|pbmac)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```