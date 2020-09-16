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
      """host":"({host}[^"]+)"""
      """vim.event.({activity}[^\s\]]+)"""
      """\[User\s([\w\.]+\\+)?({user}[^\s@\]]+).+?\s"""
      """\[User.+?@({src_ip}[^\s\]]+)""",
      """({app}VM_VCenter)"""
  ]
}
```