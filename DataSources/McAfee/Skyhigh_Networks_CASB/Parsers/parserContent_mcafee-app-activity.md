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
    """\d\d:\d\d:\d\d\s({host}[^\s]+)""",
    """devTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100} \w+)""",
    """src=(0\.0\.0\.0|({src_ip}[\da-fA-F:\.]+))""",
    """response=\[({result}[^\]\s]+)""",
    """dst=({dest_host}[^\s]+)""",
    """usrName=(({user_email}[^@]+@[^@\s]+)|({user}[^\s]+))\s{1,100}\w+=""",
    """activityName=\[({activity}[^\]\s]+)""",
    """userInfoFirstName=({user_firstname}[^\s]+)""",
    """userInfoLastName=({user_lastname}[^\s]+)""",
    """objectName=({object}[^=]+?)\s{1,100}\w+=""",
    """auditEventTypeEventTypeName=({activity}[^=]+?)\s{1,100}\w+=""",
    """serviceNames=\[({app}[^\]]+)""",
    """({app}MVISION Cloud)""",
    """eventInfo=({additional_info}[^=]+?)\s{1,100}\w+="""
  ]
}
```