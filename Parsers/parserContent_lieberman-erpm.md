#### Parser Content
```Java
{
Name = lieberman-erpm
  Vendor = Lieberman
  Product = Enterprise Random Password Manager
  Lms = Splunk
  DataType = "privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [  """Enterprise Random Password Manager""","""sEventID""","""dwBasicEventType""" ]
  Fields = [
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)Z"""",
    """\d\d:\d\d:\d\d\s({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """sEventID=\\"({event_name}[^"]+)\\"""",
    """sOriginatingSystem=\\"({src_host}[^"]+)\\"""",
    """"(sSystemName|TargetSystem)\\"\svalue=\\"({dest_host}[^"]+)\\"""",  
    """"AccountTargetName\\"\svalue=\\"({account}[^"]+)\\"""",
    """sOriginatingAccount=\\"(({domain}[^\\"]+?)\\+)?({user}[^"]+)\\"""",
    """sLoginName=\\"({target_user}[^"]+)\\"""",
    """"AccountToElevate\\"\svalue=\\"({target_user}[^"]+)\\"""",
    """ElevationGroup\\"\svalue=\\"({privileges}[^"]+)\\"""",
    """sEventType=\\"({event_type}[^"]+)\\""""
  ]
  DupFields = ["account->object"]
}
```