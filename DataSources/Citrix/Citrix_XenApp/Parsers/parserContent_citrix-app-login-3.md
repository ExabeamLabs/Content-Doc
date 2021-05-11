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
    """\sMachineName="(({domain}[^\\",]+)\\)?({host}[^\\",]+)"""",
    """\sLogOnStartDate="({time}\d\d\d\d-\d\d-\d\d\s{1,100}\d\d:\d\d:\d\d\.\d{1,100})""",
    """\sUserName="({user}[^",\s]+)"""",
    """\sClientName="(-|0+|({src_host}[^",]+?))\s{0,100}"""",
    """\sClientAddress="(::1|({src_ip}[A-Fa-f:\d.]+))"""",
    """\sOS_Type="({os}[^",]+)"""",
    """\sProtocol="({protocol}[^",]+)""""
  ]
}
```