#### Parser Content
```Java
{
Name = lieberman-erpm
  Vendor = BeyondTrust
  Product = BeyondTrust Privileged Identity
  Lms = Splunk
  DataType = "privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [  """Enterprise Random Password Manager""","""sEventID""","""dwBasicEventType""" ]
  Fields = [
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)Z"""",
    """\d\d:\d\d:\d\d\s({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"hostname":"({host}[^"]{1,2000})"""",
    """sEventID=\\"({event_name}[^"]{1,2000})\\"""",
    """sOriginatingSystem=\\"({src_host}[^"]{1,2000})\\"""",
    """"(sSystemName|TargetSystem)\\"\svalue=\\"({dest_host}[^"]{1,2000})\\"""",  
    """"AccountTargetName\\"\svalue=\\"({account}[^"]{1,2000})\\"""",
    """sOriginatingAccount=\\"(({domain}[^\\"]{1,2000}?)\\+)?({user}[^"]{1,2000})\\"""",
    """sLoginName =\\"({target_user}[^"]{1,2000})\\"""",
    """"AccountToElevate\\"\svalue=\\"({target_user}[^"]{1,2000})\\"""",
    """ElevationGroup\\"\svalue=\\"({privileges}[^"]{1,2000})\\"""",
    """sEventType=\\"({log_type}[^"]{1,2000})\\""""
  ]
  DupFields = ["account->object"]


}
```