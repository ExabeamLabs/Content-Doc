#### Parser Content
```Java
{
Name = cisco-auth-successful-2
  Vendor = Cisco
  Product = Cisco Call Manager
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "MMM dd yyyy HH:mm:ss a"
  Conditions = [ """EventType =UserLogging""", """EventStatus =Success""", """Successfully Logged into Cisco CCM Webpages""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\s({time}\w+\s+\d+\s+\d+\s+\d+:\d+:\d+\s+(AM|PM|am|pm))""",
    """UserID\s*=({user}[^\s\]]+)""",
    """ClientAddress\s*=({src_ip}[A-Fa-f:\d.]+)""",
    """EventType\s*=({activity}[^\]]+)""",
    """ResourceAccessed\s*=({object}[^\]]+)""",
    """EventStatus\s*=({outcome}[^\]]+)""",
    """ComponentID\s*=({target}[^\]]+)""",
    """AuditDetails\s*=({event_name}[^\]]+)""",
    """Node ID=({dest_host}[^\]]+)""",
    """App ID\s*=({app}[^\]]+)""",
  ]
}

${CiscoParsersTemplates.cisco-events} {
  Name = cisco-auth-failed
  Product = Cisco Call Manager
  DataType = "authentication-failed"
  Conditions = [ """EventType =UserLogging""", """=Login Authentication Failed]""" ]
}

${CiscoParsersTemplates.cisco-events} {
  Name = cisco-app-activity
  Product = Cisco Call Manager
  DataType = "app-activity"
  Conditions = [ """EventType =UserAccess""", """ResourceAccessed=""", """EventStatus =""" ]
}

{
  Name = cisco-auth-failed-1
  Vendor = Cisco
  Product = Cisco Call Manager
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "MMM dd yyyy HH:mm:ss a"
  Conditions = [ """AuthenticationFailed: """, """Login Authentication failed""", """App ID=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\s({time}\w+\s+\d+\s+\d+\s+\d+:\d+:\d+\s+(AM|PM|am|pm))""",
    """UserID\s*=({user}[^\s\]]+)""",
    """Login IP Address\/Hostname\s*=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]+))""",
    """\]:\s*({additional_info}.+?)\.?\s+$""",
    """App ID\s*=({app}[^\]]+)""",
  ]
}
```