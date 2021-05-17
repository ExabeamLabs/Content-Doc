#### Parser Content
```Java
{
Name = vmware-vcenter-activity
  Vendor = VMware
  Product = VMware VCenter
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ VIEWCENTER """ , """] [""" ]
  Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """host":"({host}[^"]{1,2000})"""
      """vim.event.({activity}[^\s\]]{1,2000})"""
      """\[User\s([\w\.]{1,2000}\\+)?({user}[^\s@\]]{1,2000}).+?\s"""
      """\[User.+?@({src_ip}[^\s\]]{1,2000})""",
      """({app}VM_VCenter)"""
  ]
}
```