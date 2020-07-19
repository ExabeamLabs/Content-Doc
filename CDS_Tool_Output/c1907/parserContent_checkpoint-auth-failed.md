#### Parser Content
```Java
{
Name = checkpoint-auth-failed
  DataType = "authentication-failed"  
  Conditions = [ """CheckPoint""", """product:"""", """action:"Failed Log In"""" ] 
}

${CheckpointParserTemplates.checkpoint-firewall-1}{
  Name = checkpoint-network-connection-4
  Conditions = [ """CheckPoint""", """product:"Security Gateway/Management"""" ]
}
```