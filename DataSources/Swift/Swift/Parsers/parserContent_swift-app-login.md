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
      """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
      """\Wdvchost=({host}[\w\-.]{1,2000})""",
      """suid=({user}[^\s]{1,2000})""",
      """({app}SWIFT)""",
      """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
      """msg=([^:]{1,2000}):\s{0,100}({user_fullname}[^,]{1,2000})""",
      """({activity}(({outcome}Successful)) signon)""",
      """msg=({additional_info}.+?)Operator Profiles:\s{0,100}({profiles}.+?)(\s{0,100}\w+=|\s{0,100}$)"""
      """msg=.+?using\s{0,100}\'({platform}[^\']{1,2000})"""
    ]
  }
```