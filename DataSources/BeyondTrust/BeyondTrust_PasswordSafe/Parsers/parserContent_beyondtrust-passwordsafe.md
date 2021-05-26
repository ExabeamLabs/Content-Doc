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
    """LogTime:\s{0,100}({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """User:\s{0,100}(({domain}[^\\]{1,2000})\\+)?({user}.+?)\s{1,100}(\w+\s)?\w+:""",
    """Source Host:\s{0,100}({host}[^\s]{1,2000})""",
    """Event Subject:\s{0,100}0*({src_ip_1}\d{1,100}\.)0*({src_ip_2}\d{1,100}\.)0*({src_ip_3}\d{1,100}\.)0*({src_ip_4}\d{1,100})""",
    """Target:.*?Asset:({dest_host}[^\s]{1,2000})\s{1,100}\w+:""",
    """Target:.*?MAccount:({account}[^\s]{1,2000})\s{1,100}\w+:""",
    """RoleUsed:\s{0,100}({privileges}.+?)\s{1,100}\w+:""",
    """Agent ID:\s{0,100}({event_code}PBPS)"""
  ]
}
```