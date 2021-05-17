#### Parser Content
```Java
{
Name = tripwire-file-alert-1
  Vendor = Tripwire Enterprise
  Product = Tripwire Enterprise
  Lms = Splunk
  DataType = "file-alert"  
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """TRIPWIRE""", """ Modify:""" , """ on """, """ by """  ]

  Fields = [
   """\s({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s""",
   """(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s({host}[^\s]{1,2000}?)\sModify:""",
   """\s{1,100}Modify:\s{1,100}({accesses}[A-Za-z]{1,2000}?)\s{1,100}""",
   """\sModified\s({file_path}[^|]{1,2000}?)\son\s""",
   """\sModified\s({file_parent}[^|]{1,2000}?)[\\\/]{1,2000}[^\\\/]{1,2000}\son\s""",
   """\sModified\s([^|]{0,2000}?[\\\/]{1,2000})?({file_name}[^\\\/|]{1,2000})\son\s""",
   """\sModified\s[^|]{1,2000}?[\\\/]{1,2000}[^\\\/|.]{1,2000}\.({file_ext}[^\\\/|]{1,2000})(\son\s)""",
   """\son\s({dest_host}[^\s]{1,2000}?)\sby\s""",
   """\sby\s({alert_name}.+?)\s{0,100}$""",
   """({alert_type}Modify)"""
   ]
SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_type->description"]
    NameTemplate = """Tripwire Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_host->host_name"]}
```