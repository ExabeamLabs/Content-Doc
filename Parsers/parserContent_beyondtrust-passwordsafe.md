#### Parser Content
```Java
{
Name = beyondtrust-passwordsafe
  Vendor = BeyondTrust
  Product = BeyondTrust PasswordSafe
  Lms = Direct
  DataType = "privileged-access"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [  """Event Desc: Password Retrieve""","""Agent ID: PBPS""","""Failed: False""" ]
  Fields = [
    """LogTime:\s*({time}\d+\/\d+\/\d+ \d+:\d+:\d+)""",
    """User:\s*(({domain}[^\\]+)\\+)?({user}.+?)\s+(\w+\s)?\w+:""",
    """Source Host:\s*({host}[^\s]+)""",
    """Event Subject:\s*0*({src_ip_1}\d+\.)0*({src_ip_2}\d+\.)0*({src_ip_3}\d+\.)0*({src_ip_4}\d+)""",
    """Target:.*?Asset:({dest_host}[^\s]+)\s+\w+:""",
    """Target:.*?MAccount:({account}[^\s]+)\s+\w+:""",
    """RoleUsed:\s*({privileges}.+?)\s+\w+:""",
    """Agent ID:\s*({event_code}PBPS)"""
  ]
}
```