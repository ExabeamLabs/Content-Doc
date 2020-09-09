#### Parser Content
```Java
{
Name = s-4662
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "object-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [""",4662,""", """An operation was performed on an object"""]
  Fields = [
    """({event_name}An operation was performed on an object)""",
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+),""",
    """({outcome}(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)),({host}[^\s,]+)""",
    """Account Name:\s*({user}.+?)\s*Account Domain""",
    """Account Domain:\s*({domain}.+?)\s*Logon ID""",
    """Logon ID:\s*({logon_id}[^\s]+)""",
    """Object Server:\s*({object_class}.+?)\s*Object Type:""",
    """Object Type:\s*({activity_type}.+?)\s*Object Name:""",
    """Object Name:\s*({object}.+?)\s*Handle ID:""",
    """Operation Type:\s*({action}.+?)\s*Accesses:""",
    """Properties:\s*(?:-|({properties}.+?))\s*Additional Information:""",
    """Additional Information:\s*({attribute}[^,]+)""",
    """({event_code}4662)"""
  ]
  DupFields = [ "host->dest_host" ]
}

{
  Name = raw-4738
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "account-modification"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = ["""A user account was changed"""]
  Fields = [
    """({event_name}A user account was changed)""",
    """({event_code}4738)""",
    """Computer(Name)?\s*\\*"?(=|:|>)\s*"*({host}[\w\.-]+)(\s|,|"|</Computer>|$)""",
    """\sComputerName=({host}.+?)(\s+\w+=|\s*$)""",
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """Security ID:\s*(|({user_sid}.+?))\s+Account Name:""",
    """Account Name:\s*(|({user}.+?))\s+Account Domain:\s*(|({domain}.+?))\s+Logon ID:\s*(|({logon_id}.+?))\s+Target Account:""",
    """Target\sAccount.+?Security ID:\s*({target_sid}.+?)\s""",
    """Target\sAccount.+?Account Name:\s*({target_user}.+?)\s""",
    """Target\sAccount.+?Account Domain:\s*({target_domain}.+?)\s""",
    """Changed Attributes:\s*(|({attribute}.+?))\s+SAM Account Name"""
  ]
}
```