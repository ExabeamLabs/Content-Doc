#### Parser Content
```Java
{
Name = cef-beyondtrust-app-activity
  Conditions = [ """cat=System""", """CEF:""", """|BeyondTrust|BeyondInsight|""", """|PBPS|Administrators|""" ]

cef-beyondtrust-app-activity-events = {
  Vendor = BeyondTrust
  Product = BeyondInsight
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """rt=({time}\w{3} \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """BeyondTrustBeyondInsightClientHost=({host}[\w.-]{1,2000})""",
    """\ssrc=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """\sdst=({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """\sduser=(-|({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000})|((({domain}[^\s]{1,2000}?)[\\]{1,20})?({user}[\w.-]{1,2000})))""",
    """\ssuser=(-|({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000})|((({domain}[^\s]{1,2000}?)[\\]{1,20})?({user}[\w.-]{1,2000})))""",
    """Operation=({activity}[^=]{1,2000}?)\s\w+=""",
    """ObjectType=({object_type}[^=]{1,2000}?)\s\w+=""",
    """ObjectID=({object_id}[^=]{1,2000})\s\w+=""",
    """({app}BeyondInsight)"""
  
}
```