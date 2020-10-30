#### Parser Content
```Java
{
Name = crowdstrike-config-change
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "config-change"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"Firewall""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"timestamp":"({time}\d+)""",
      """"event_simpleName":"({activity}[^"]+)""",
      """"aid":"({aid}[^"]+)""",
      """"FirewallRule":"({object}[^"]+)""",
      """ext_UserName=({user}[^\s"]+)\s+(\w+=|$)""",
    ]
    DupFields = ["activity->event_code"]
  }
```