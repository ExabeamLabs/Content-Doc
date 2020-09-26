#### Parser Content
```Java
{
Name = q-duo-auth-successful
  Vendor = Duo Security
  Product = Duo Access Security
  Lms = QRadar
  DataType = "authentication-successful"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """factor=""", """result=SUCCESS;""", """new_enrollment=""" ]
  Fields = [
    """\d\d:\d\d\s+({host}.+?)\s+(\S+\s+)*@\{\w+=""",
    """\Wdevice=\s*({device}[^;]+?)(?:;|\})""",
    """\Wintegration=\s*({integration}[^;]+?)(?:;|\})""",
    """\Wip=\s*(?:0\.0\.0\.0|({src_ip}[a-fA-F\d.:]+))""",
    """\Wresult=\s*({outcome}[^;]+?)(?:;|\})""",
    """timestamp=\s*({time}\d+\/\d+\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wusername=\s*({user}[^;]+?)(?:;|\})""",
    """\Wnew_enrollment=\s*({new_enrollment}[^;]+?)(?:;|\})""",
  ]
}
```