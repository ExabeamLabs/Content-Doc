#### Parser Content
```Java
{
Name = u-duo-auth-json
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Sumo
  DataType = "authentication-attempt"
  TimeFormat = "epoch_sec"
  Conditions = [ """eventtype="authentication"""", """newenrollment="""", """ip="""", """result=""""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """host="({host}[\w\-\.]{1,2000})"""",
    """(^|exabeam_\w+=)({time}\d{10}),""",
    """\Wip="(0.0.0.0|({src_ip}[a-fA-F:\.\d]{1,2000}))"""",
    """\Wusername="(?:({domain}[^\\"]{1,2000})\\)?({user}[^"]{1,2000})"""",
    """\Wfactor="(?:n\/a|({auth_method}[^"]{1,2000}))"""",
    """\Wresult="({outcome}[^"]{1,2000})"""",
    """\Wreason="({failure_reason}[^"]{1,2000})"""",
    """\Wnewenrollment="({new_enrollment}True|False)"""
  ]
}
```