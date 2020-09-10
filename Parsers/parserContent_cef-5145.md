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
          """\Wrt=({time}\d+)""",
          """\Wsrc=({src_ip}[A-Fa-f0-9.:]+)""",
          """\Wdhost=({dest_host}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
          """\Wdvchost=({host}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
          """\Wdst=({dest_ip}[A-Fa-f0-9.:]+)""",
          """\Wdntdom=({domain}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
          """\Wduser=({user}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
          """\Wduid=({login_id}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
          """\WcategoryOutcome=\/?({outcome}\w+)""",
          """\W\ad\.ShareName=(?:\\+\*\\+)?({share_name}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
          """\Wcs1=.*?({accesses}SYNCHRONIZE|Execute|Traverse|Read|READ).*?(\s+(\w+|\w+\.\w+)=|\s*$)""",
          """\Wcs1=.*?({accesses}WRITE_DAC|WRITE_OWNER|WriteAttributes|WriteEA).*?(\s+(\w+|\w+\.\w+)=|\s*$)""",
          """\Wcs1=.*?({accesses}WriteData|AppendData).*?(\s+(\w+|\w+\.\w+)=|\s*$)""",
          """\Wcs1=.*?({accesses}delete|Delete).*?(\s+(\w+|\w+\.\w+)=|\s*$)""",
          """\Wad\.ShareLocalPath=(?:[\\\?]+)?(?:\s*|({share_path}({d_parent}.*?)({d_name}[^\\]+?))(\\+)?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
          """\Wad\.RelativeTargetName=(({f_parent}.*?)({file_name}[^\\:]+?(\.({file_ext}[^\\.]+?))?))(\s+(\w+|\w+\.\w+)=|\s*$)""",
          """\Wad\.ObjectType=({file_type}\w+)""",
        ]
}
```