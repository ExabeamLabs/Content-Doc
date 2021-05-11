#### Parser Content
```Java
{
Name = q-duo-auth-failed
  Vendor = Cisco
  Product = Duo Access Security
  Lms = QRadar
  DataType = "authentication-failed"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """reason=""", """result=FAILURE;""", """new_enrollment=""" ]
  Fields = [
    """\d\d:\d\d\s{1,100}({host}.+?)\s{1,100}(\S+\s{1,100})*@\{\w+=""",
    """\Wdevice=\s{0,100}({device}[^;]+?)(?:;|\})""",
    """\Wintegration=\s{0,100}({integration}[^;]+?)(?:;|\})""",
    """\Wip=\s{0,100}(?:0\.0\.0\.0|({src_ip}[a-fA-F\d.:]+))""",
    """\Wresult=\s{0,100}({outcome}[^;]+?)(?:;|\})""",
    """\Wreason=\s{0,100}({failure_reason}[^;]+?)(?:;|\})""",
    """timestamp=\s{0,100}({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wusername=\s{0,100}({user}[^;]+?)(?:;|\})""",
    """\Wnew_enrollment=\s{0,100}({new_enrollment}[^;]+?)(?:;|\})""",
  ]
}
```