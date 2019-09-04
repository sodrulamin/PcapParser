package pcapparser;

public class Version 
{
	public int major, minor, build;
	
	public Version()
	{
		major = minor = build =0;
	}

	public Version(int value)
	{
		major = (value >> 16)&0x00FF;
		minor = (value >> 8)&0x00FF;
		build = value &0x00FF;
	}
	
	public void init()
	{
		major = minor = build =0;
	}
	
	public int compare(String p_version)
	{
		int index = 0;
		for(;index<p_version.length();)
		{
			if(p_version.charAt(index)<'0'||p_version.charAt(index)>'9')index++;
			else break;
		}
		int p_major=0;
		for(;index<p_version.length();index++)
		{
			if(p_version.charAt(index)<'0'||p_version.charAt(index)>'9')break;
			p_major = p_major * 10 + p_version.charAt(index) -'0';
		}

		if(major!=p_major)
			return major - p_major;
		for(;index<p_version.length();)
		{
			if(p_version.charAt(index)<'0'||p_version.charAt(index)>'9')index++;
			else break;
		}
		
		int p_minor=0;
		for(;index<p_version.length();index++)
		{
			if(p_version.charAt(index)<'0'||p_version.charAt(index)>'9')break;
			p_minor = p_minor * 10 + p_version.charAt(index) -'0';
		}

		if(minor!=p_minor)return minor - p_minor;
		
		for(;index<p_version.length();)
		{
			if(p_version.charAt(index)<'0'||p_version.charAt(index)>'9')index++;
			else break;
		}
		
		int p_build=0;
		for(;index<p_version.length();index++)
		{
			if(p_version.charAt(index)<'0'||p_version.charAt(index)>'9')break;
			p_build = p_build * 10 + p_version.charAt(index) -'0';
		}		

		return build - p_build;
	}
	
	public void parse(byte []data, int offset, int length)
	{
		int index = offset;
		for(;index<offset+length;)
		{
			if(data[index]<'0'||data[index]>'9')index++;
			else break;
		}
		major=0;
		for(;index<offset+length;index++)
		{
			if(data[index]<'0'||data[index]>'9')break;
			major = major * 10 + data[index] -'0';
		}

		for(;index<offset+length;)
		{
			if(data[index]<'0'||data[index]>'9')index++;
			else break;
		}
		
		minor=0;
		for(;index<offset+length;index++)
		{
			if(data[index]<'0'||data[index]>'9')break;
			minor = minor * 10 + data[index] -'0';
		}

		
		for(;index<offset+length;)
		{
			if(data[index]<'0'||data[index]>'9')index++;
			else break;
		}
		
		build=0;
		for(;index<offset+length;index++)
		{
			if(data[index]<'0'||data[index]>'9')break;
			build = build * 10 + data[index] -'0';
		}		
	}
	
	public String toString()
	{
		return major+"."+minor+"."+build;
	}
	
	public int toInt()
	{
		return (major<<16)|(minor<<8)|build;
	}
	/*public static void main(String args[])
	{
		Version v = new Version();
		String testVersion[]={"1.0.4","2.14(0)","2.10.1"};
		
		for(int i=0;i<testVersion.length;i++)
		{
			System.out.println("Original:"+testVersion[i]);
			byte []data = testVersion[i].getBytes();
			v.parse(data, 0, data.length);
			System.out.println("Converted:"+v);
		}	
		
	}*/
}
