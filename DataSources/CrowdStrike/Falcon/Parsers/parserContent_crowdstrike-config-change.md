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
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
      """"timestamp":"({time}\d{1,100})""",
      """"event_simpleName":"({activity}[^"]+)""",
      """"aid":"({aid}[^"]+)""",
      """"FirewallRule":"({object}[^"]+)""",
      """ext_UserName=({user}[^\s"]+)\s{1,100}(\w+=|$)""",
      """src-account-name":"({account_name}[^"]+)""",
    ]
    DupFields = ["activity->event_code"]
  }
```