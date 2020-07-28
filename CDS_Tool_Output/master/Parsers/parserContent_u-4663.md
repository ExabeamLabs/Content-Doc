#### Parser Content
```Java
{
Name = u-4663
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Sumo
  DataType = "windows-4663"
  IsHVF = true
  TimeFormat = "yyyyMMddHHmmss"
  Conditions = [ "EventCode = 4663;", """An attempt was made to access an object.""" ]
  Fields = [ """Computer(Name)? = "+({host}[^"]+)"""",
    """({event_name}An attempt was made to access an object)""",
             """EventCode = ({event_code}\d+)""",
             """TimeGenerated = "({time}[\d]+)\.\d\d\d""",
             """Account Name:\s+(?:|({user}.+?))\s+Account Domain:\s+(?:|({domain}.+?))\s+Logon ID:""",
             """Process Name:\s+(?:|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/]+?)))\s+Access Request""",
             """Logon ID:\s+({logon_id}[^\s]+)\s+Object:""",
             """Security ID:\s+({user_sid}[^\s]+)\s""",
             """Accesses:\s+(?:|({accesses}.+?))\s+Access Mask:\s*({access_mask}\w+)?""",
             """Object Name:.*\\({file_name}(?:[^\\:]+(?=\.))({file_ext}\.[^\\:\s]+)?|[^\\:\s]+)\s+Handle ID:""",
             """Object Name:\s+(?:|({file_parent}.+?)\\(?:[^\\]+?))\s+Handle ID:""",
             """Object Type:\s+(?:|({file_type}.+?))\s+Object Name:"""
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```