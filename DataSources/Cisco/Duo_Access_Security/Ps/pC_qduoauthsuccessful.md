#### Parser Content
```Java
{
Name = q-duo-auth-successful
  Vendor = Cisco
  Product = Duo Access Security
  Lms = QRadar
  DataType = "authentication-successful"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """factor=""", """result=SUCCESS;""", """new_enrollment=""" ]
  Fields = [
    """\d\d:\d\d\s{1,100}({host}.+?)\s{1,100}(\S+\s{1,100})*@\{\w+=""",
    """\Wdevice=\s{0,100}({device}[^;]{1,2000}?)(?:;|\})""",
    """\Wintegration=\s{0,100}({integration}[^;]{1,2000}?)(?:;|\})""",
    """\Wip=\s{0,100}(?:0\.0\.0\.0|({src_ip}[a-fA-F\d.:]{1,2000}))""",
    """\Wresult=\s{0,100}({outcome}[^;]{1,2000}?)(?:;|\})""",
    """timestamp=\s{0,100}({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wusername=\s{0,100}({user}[^;]{1,2000}?)(?:;|\})""",
    """\Wnew_enrollment=\s{0,100}({new_enrollment}[^;]{1,2000}?)(?:;|\})""",
  ]
}
```