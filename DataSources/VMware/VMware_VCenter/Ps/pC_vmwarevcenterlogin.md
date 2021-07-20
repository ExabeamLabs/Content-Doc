#### Parser Content
```Java
{
Name = vmware-vcenter-login
  Vendor = VMware
  Product = VMware VCenter
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ VIEWCENTER """ , """Authenticated user""" ]
  Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """host":"({host}[^"]{1,2000})"""
      """vim.event.({activity}[^\s\]]{1,2000})""",
      """Authenticated user ({user}[^\s@]{1,2000})""",
      """({app}VM_VCenter)"""
  ]
}
```