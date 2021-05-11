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
  Fields = [ """Computer(Name)? = "{1,20}({host}[^"]+)"""",
    """({event_name}An attempt was made to access an object)""",
             """EventCode = ({event_code}\d{1,100})""",
             """TimeGenerated = "({time}[\d]+)\.\d\d\d""",
             """Account Name:\s{1,100}(?:|({user}.+?))\s{1,100}Account Domain:\s{1,100}(?:|({domain}.+?))\s{1,100}Logon ID:""",
             """Process Name:\s{1,100}(?:|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/]+?)))\s{1,100}Access Request""",
             """Logon ID:\s{1,100}({logon_id}[^\s]+)\s{1,100}Object:""",
             """Security ID:\s{1,100}({user_sid}[^\s]+)\s""",
             """Accesses:\s{1,100}(?:|({accesses}.+?))\s{1,100}Access Mask:\s{0,100}({access_mask}\w+)?""",
             """Object Name:.*\\({file_name}(?:[^\\:]+(?=\.))({file_ext}\.[^\\:\s]+)?|[^\\:\s]+)\s{1,100}Handle ID:""",
             """Object Name:\s{1,100}(?:|({file_parent}.+?)\\(?:[^\\]+?))\s{1,100}Handle ID:""",
             """Object Type:\s{1,100}(?:|({file_type}.+?))\s{1,100}Object Name:"""
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```