import java.io.File; 
 	import java.io.FileInputStream; 
 	import java.io.FileReader; 
 	import java.io.IOException; 
 	
 	public class Prover { 
 	
 		public static 	int metaBit;
 		public static 	String enc_metaBlock="";
 		

 	public static void metadata_Rertieve(String filename, int numBlock, int posInBlock, int n, int bytesToSkip, int k) throws IOException{ 
 	File file = new File("../" + filename); 
 	FileInputStream inStream = new FileInputStream(file); 
	
 	inStream.skip((int)(numBlock*n + posInBlock/8)); 
 	byte b = (byte) inStream.read(); 
 	int pos = posInBlock%8; 
 	int c = b & (1 << pos); 
 	if(c != 0){ 
 	c=1;  	
 	} 
 	inStream.close(); 
 	Prover.metaBit= c;  
 
 	FileReader ir = new FileReader(file); 
 	ir.skip(bytesToSkip); 
 	byte data[] = new byte[k/4 + 32]; 
 	for (int i=0; i < (k/4 + 32); i++){ 
 	data[i] = (byte) ir.read(); 
 	} 
 	String enc = new String(data); 
 	ir.close(); 
 	Prover.enc_metaBlock= enc;  	
 	}  	 	
 	} 

 	
