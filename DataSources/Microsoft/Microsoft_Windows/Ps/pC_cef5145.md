#### Parser Content
```Java
{
Name = cef-5145
        Vendor = Microsoft
        Product = Microsoft Windows
        Lms = ArcSight
        DataType = "share-access"
        TimeFormat = "epoch"
        Conditions = ["CEF:", "|Microsoft|Microsoft Windows|", "|A network share object was checked to see whether client can be granted desired access.|"]
        Fields = [
          """({event_name}A network share object was checked to see whether client can be granted desired access)""",
          """({event_code}5145)""",
          """\Wrt=({time}\d{1,100})""",
          """\Wsrc=({src_ip}[A-Fa-f0-9.:]{1,2000})""",
          """\Wdhost=({dest_host}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\Wdvchost=({host}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\Wdst=({dest_ip}[A-Fa-f0-9.:]{1,2000})""",
          """\Wdntdom=({domain}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\Wduser=({user}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\Wduid=({login_id}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\WcategoryOutcome=\/?({outcome}\w+)""",
          """\W\ad\.ShareName =(?:\\+\*\\+)?({share_name}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\Wcs1=.*?({accesses}SYNCHRONIZE|Execute|Traverse|Read|READ).*?(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\Wcs1=.*?({accesses}WRITE_DAC|WRITE_OWNER|WriteAttributes|WriteEA).*?(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\Wcs1=.*?({accesses}WriteData|AppendData).*?(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\Wcs1=.*?({accesses}delete|Delete).*?(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\Wad\.ShareLocalPath=(?:[\\\?]{1,2000})?(?:\s{0,100}|({share_path}({d_parent}.*?)({d_name}[^\\]{1,2000}?))(\\+)?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\Wad\.RelativeTargetName =(({f_parent}.*?)({file_name}[^\\:]{1,2000}?(\.({file_ext}[^\\.]{1,2000}?))?))(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\Wad\.ObjectType=({file_type}\w+)""",
        ]


}
```