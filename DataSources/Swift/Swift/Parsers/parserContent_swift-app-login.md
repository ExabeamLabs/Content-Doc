#### Parser Content
```Java
{
Name = swift-app-login
    Vendor = Swift
    Product = Swift
    Lms = Splunk
    DataType = "app-login"
    TimeFormat = "epoch"
    Conditions = [ """|SWIFT|""", """|Successful signon|"""]
    Fields = [
      """rt=({time}\d{1,100})""",
      """\Wdvc=({host}[A-Fa-f:\d.]+)""",
      """\Wdvchost=({host}[\w\-.]+)""",
      """suid=({user}[^\s]+)""",
      """({app}SWIFT)""",
      """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
      """msg=([^:]+):\s{0,100}({user_fullname}[^,]+)""",
      """({activity}(({outcome}Successful)) signon)""",
      """msg=({additional_info}.+?)Operator Profiles:\s{0,100}({profiles}.+?)(\s{0,100}\w+=|\s{0,100}$)"""
      """msg=.+?using\s{0,100}\'({platform}[^\']+)"""
    ]
  }
```