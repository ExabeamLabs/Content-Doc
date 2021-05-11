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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """host="({host}[\w\-\.]+)"""",
    """(^|exabeam_\w+=)({time}\d{10}),""",
    """\Wip="(0.0.0.0|({src_ip}[a-fA-F:\.\d]+))"""",
    """\Wusername="(?:({domain}[^\\"]+)\\)?({user}[^"]+)"""",
    """\Wfactor="(?:n\/a|({auth_method}[^"]+))"""",
    """\Wresult="({outcome}[^"]+)"""",
    """\Wreason="({failure_reason}[^"]+)"""",
    """\Wnewenrollment="({new_enrollment}True|False)"""
  ]
}
```