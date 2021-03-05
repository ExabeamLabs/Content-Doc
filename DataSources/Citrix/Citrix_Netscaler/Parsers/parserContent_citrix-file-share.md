#### Parser Content
```Java
{
Name = citrix-file-share
  DataType = "app-activity"
  Vendor = Citrix
  Product =  Citrix Netscaler
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = ["""SkyFormation""","""destinationServiceName=Citrix ShareFile"""]
  Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d+Z)\s({host}[^ ]+)""",
      """cat=({category}[^ ]+)""",
      """fname=({file_name}[^ ]+)""",
      """suser=({user_email}[^ ]+)""",
      """destinationServiceName=({app}.+?)\s*\w+=""",
      """dproc=({activity}[^\s]+)""",
      """ext_RecipientEmail=({target}[^\s]+)"""
  ]
}
```