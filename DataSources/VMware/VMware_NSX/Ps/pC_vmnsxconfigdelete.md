#### Parser Content
```Java
{
Name = vm-nsx-config-delete
 Conditions= [ """Avi-Controller""", """event CONFIG_DELETE""" ,"""success""" ]
 
nsx-config-change-activity = {
    Vendor = VMware
    Product = VMware NSX
    Lms = Direct
    TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
    DataType = "config-change"
    Fields = [
      """({host}[\w\-\.]{1,2000})\sAvi-Controller""",
      """event\s({activity}[^\s]{1,2000})""",
      """({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d.\d\d:\d\d)\sevent""",
      """occurred on object ({object}[^\s]{1,200})""",
      """({outcome}success)""",
      """tenant\s({tenant}[\w\-\.]{1,2000})\s""",
      """by user ({user}[\w\-\.]{1,2000})"""
    
}
```