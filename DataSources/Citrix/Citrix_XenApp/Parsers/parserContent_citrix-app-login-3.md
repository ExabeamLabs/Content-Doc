#### Parser Content
```Java
{
Name = citrix-app-login-3
  Vendor = Citrix
  Product = Citrix XenApp
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """LogOnStartDate="""", """UserName=""", """MachineName=""", """DeliveryGroup=""" ]
  Fields = [
    """\sMachineName="(({domain}[^\\",]{1,2000})\\)?({host}[^\\",]{1,2000})"""",
    """\sLogOnStartDate="({time}\d\d\d\d-\d\d-\d\d\s{1,100}\d\d:\d\d:\d\d\.\d{1,100})""",
    """\sUserName="({user}[^",\s]{1,2000})"""",
    """\sClientName="(-|0+|({src_host}[^",]{1,2000}?))\s{0,100}"""",
    """\sClientAddress="(::1|({src_ip}[A-Fa-f:\d.]{1,2000}))"""",
    """\sOS_Type="({os}[^",]{1,2000})"""",
    """\sProtocol="({protocol}[^",]{1,2000})""""
  ]
}
```