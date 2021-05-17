#### Parser Content
```Java
{
Name = mcafee-app-activity
  Vendor = McAfee
  Product = Skyhigh Networks CASB
  Lms = QRadar
  DataType = "app-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
  Conditions = [  """|McAfee|MVISION Cloud|""", """usrName=""", """devTime=""", """cat="""]
  Fields = [
    """\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})""",
    """devTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100} \w+)""",
    """src=(0\.0\.0\.0|({src_ip}[\da-fA-F:\.]{1,2000}))""",
    """response=\[({result}[^\]\s]{1,2000})""",
    """dst=({dest_host}[^\s]{1,2000})""",
    """usrName=(({user_email}[^@]{1,2000}@[^@\s]{1,2000})|({user}[^\s]{1,2000}))\s{1,100}\w+=""",
    """activityName=\[({activity}[^\]\s]{1,2000})""",
    """userInfoFirstName=({user_firstname}[^\s]{1,2000})""",
    """userInfoLastName=({user_lastname}[^\s]{1,2000})""",
    """objectName=({object}[^=]{1,2000}?)\s{1,100}\w+=""",
    """auditEventTypeEventTypeName=({activity}[^=]{1,2000}?)\s{1,100}\w+=""",
    """serviceNames=\[({app}[^\]]{1,2000})""",
    """({app}MVISION Cloud)""",
    """eventInfo=({additional_info}[^=]{1,2000}?)\s{1,100}\w+="""
  ]
}
```