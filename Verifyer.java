
import javax.crypto.*; 
import javax.crypto.spec.*; 
import java.io.*; 
import java.security.InvalidKeyException; 
import java.security.NoSuchAlgorithmException; 
import java.text.DecimalFormat; 
import java.util.ArrayList; 
import java.util.Collections; 
import java.util.HashSet; 
import java.util.List; 
import java.util.Random; 
import java.util.Set; 

import javax.xml.bind.DatatypeConverter; 

	public class Verifyer { 
		
	 int[][][] meta; 	
	 int totalByte; 	
	 int numBlocks; 
	 
	//Class Constuctor
	 
	public Verifyer(int[][][] met, int totalByte, int numBlocks) { 
		
	this.meta = met; 	
	
	this.totalByte = totalByte; 	
	
	this.numBlocks = numBlocks; 
	
	} 
	
	//=======================================================================================
	// method for file Integrity Verifying
	
	public static boolean integrity_Verify (String filename, int blockNum, int posInBlock,	int n, int k, int bytesToSkip, int posInTable) 
	throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, 
	InvalidKeyException, IllegalBlockSizeException, BadPaddingException { 
	
	boolean res = false; 
	Prover.metadata_Rertieve(filename, blockNum, posInBlock, n, bytesToSkip, k);
	int metaBit = Prover.metaBit; 

	String metaBlockEnc = Prover.enc_metaBlock; 
 
	FileInputStream keyInFile; 
	
	String keyFile = "../" + filename + "_local/key" + blockNum + ".txt"; 
	
	try{ 
	keyInFile = new FileInputStream(keyFile); 
	byte[] secretKeyBytes = new byte[16]; 
	keyInFile.read(secretKeyBytes); 
	SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "AES"); 
	keyInFile.close(); 
	try{ 
	Cipher cipher = Cipher. getInstance("AES"); 
	cipher.init(Cipher. DECRYPT_MODE, secretKey); 
	byte[] b = DatatypeConverter. parseHexBinary(metaBlockEnc); 
	byte[] orig = cipher.doFinal(b); 
	byte metaB = orig[posInTable/8]; 
	int bit = posInTable%8; 
	int c = metaB & (1 << bit); 
	if(c != 0){ 
	c=1; 
	} 
	if (metaBit == c){ 
	res = true; 
	}
	if (res==false){ 
	FileWriter fwr = new FileWriter(new File(new File(System. getProperty("user.dir")).getParent() + "/" + filename + "_local", "incorr.txt"), true); 
	fwr.append(blockNum + ", "); 
	fwr.close(); 
	}
	}
	catch(Exception e){ 
	System. out.println("The file is corrupted. Portion of the file has been deleted."); 
	System. exit(0); 
	}
	}
	catch(Exception e){ 
	System. out.println("The name of the file is wrong."); 
	System. exit(0); 
	} 
	return res; 
	} 

	//=======================================================================================
	// method for file Integrity Verifing
	public static Verifyer config(String fileName, int n, int k) 
	
	
	throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{ 
	File file = new File(new File(System. getProperty("user.dir")).getParent(), fileName); 
	
	FileInputStream inStream = new FileInputStream(file); 
	File dir = new File(new File(System. getProperty("user.dir")).getParent(), fileName + "_local"); 
	//deleting the directory if it exists. 
	if (dir.exists()){ 
	if (dir.isDirectory()) { 
	File[] children = dir.listFiles(); 
	for (int i=0; i<children.length; i++) { 
	children[i].delete(); 
	}
	}
	}	
	//creating a directory that will archive the files that will serve the execution of the verification process. 
	dir.mkdir(); 
	File fileEnc = new File(new File(System. getProperty("user.dir")).getParent(), fileName + "_local/"+ "out"); 
	FileWriter outStreamEnc = new FileWriter(fileEnc, true); 
	
	File f = new File(new File(System. getProperty("user.dir")).getParent(), fileName +"_local/results.txt"); 
	FileWriter stat = new FileWriter(f); 
	long totalByte = inStream.available(); 
	//total number of blocks in the file 
	int numBlocks = (int)totalByte/n; 
	if ((int)totalByte % n != 0){ 
	numBlocks = numBlocks+1; 
	} 
	int[][][] m = new int[numBlocks][2][k]; 
	DecimalFormat df = new DecimalFormat("#.##"); 
	stat.flush(); 

	KeyGenerator kgen = KeyGenerator. getInstance("AES"); 
	kgen.init(128); 

	int i = 0; 
	while (inStream.available() > 0){ 

	Set<Integer> numbers = new HashSet<Integer>(); 

	while(numbers.size() < k){ 
	Random r = new Random(); 
	int num = r.nextInt(n*8); 
	numbers.add(num);
	}
	ArrayList<Integer> meta = new ArrayList<Integer>(numbers); 

	Collections. sort(meta);

	int count = 0; 
	inStream.skip(meta.get(count)/8);

	while (count < k && inStream.available() > 0){ 
	byte b = (byte) inStream.read(); 

	m[i][0][count] = meta.get(count); 

	int pos = meta.get(count)%8; 
	if ((b & (1 << pos)) == 0){ 
	m[i][1][count] = 0; 
	} 
	else{ 
	m[i][1][count] = 1; 
	} 

	while(count < k-1 && meta.get(count+1)/8 == meta.get(count)/8){ 
	count = count + 1; 
	m[i][0][count] = meta.get(count); 
	pos = meta.get(count)%8; 

	if ((b & (1 << pos)) == 0){ 

	m[i][1][count] = 0; 
	}
	else{ 
	m[i][1][count] = 1; 
	}
	}
	count++;
	if (count < k){ 

	inStream.skip((int)(meta.get(count)/8 - meta.get(count-1)/8 - 1)); 
	} 
	else{ 
	inStream.skip((int)(n - meta.get(count-1)/8 - 1)); 
	}
	}

	if (count >= k || inStream.available() <= 0) { 
	byte[] newByte = new byte[k/8]; 

	for(int j = 0; j < m[i][1].length;){ 

	for(int pos = 0; pos < k/8; pos++){ 

	byte b = 0; 

	for(int bit = 0; bit < 8; bit++){ 

	if(m[i][1][j] == 1){ 

	b |= 1 << bit; 
	}
	else if (m[i][1][j] == 0){ 

	b &= ~(1 << bit); 
	}
	j++; 
	}
	newByte[pos] = b; 
	}
	} 	
	SecretKey skey = kgen.generateKey(); 

	byte[] raw = skey.getEncoded(); 

	String keyFile = "../" + fileName + "_local/key" + i + ".txt"; 

	FileOutputStream keyOutFile; 
	try {  

	keyOutFile = new FileOutputStream(keyFile); 

	keyOutFile.write(raw); 

	keyOutFile.close(); 

	} catch (FileNotFoundException e) { 
	e.printStackTrace(); 

	} 	
	SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES"); 
	
	Cipher cipher = Cipher. getInstance("AES");
	cipher.init(Cipher. ENCRYPT_MODE, skeySpec); 
	
	byte[] encrypted = cipher.doFinal(newByte); 	
	String bytesAsString = DatatypeConverter. printHexBinary(encrypted); 	

	outStreamEnc.write(bytesAsString); 
	outStreamEnc.flush(); 

	if (i==numBlocks-2){ 
	n = (int)totalByte % n; 
	} 
	i++; 
	}
	}
	inStream.close(); 
	outStreamEnc.close(); 
	numBlocks = i; 
	FileOutputStream outStream = new FileOutputStream(file, true); 
	FileInputStream inStreamEnc = new FileInputStream(fileEnc); 
	int bytesEnc = (int) fileEnc.length(); 
	byte[] bytes = new byte[k/8]; 
	while (inStreamEnc.available() > 0){ 
	inStreamEnc.read(bytes);
	outStream.write(bytes); 
	outStream.flush(); 
	} 
	outStream.close(); 
	inStreamEnc.close(); 
	fileEnc.delete();	 
	stat.close(); 	
	Verifyer client = new Verifyer(m, (int)totalByte, numBlocks);	
	return client; 
	} 
	
	//=======================================================================================
	
	public static void main(String[] args) throws Exception { 
	int n = 768;//block size in bytes(B) 128B=1024bits 768B=6144bits 
	
	int k = 256;//number of meta bits in a block 
	if (args[0].equals("config")){ 
	
	Verifyer client = config(args[1], n, k); 
	int[][] m = new int[client.numBlocks][client.meta[0][0].length]; //m[block][position of the bit in the table] 
	//- position of the bit in the block 
	
	for (int i=0; i<client.numBlocks; i++){ 
	for (int j=0; j<client.meta[i][0].length; j++){ 
	m[i][j] = client.meta[i][0][j]; 	
	} 	
	} 
	new ObjectOutputStream(new FileOutputStream(new File(new 
	File(System. getProperty("user.dir")).getParent() + "/" + args[1] + "_local", "m"))).writeObject(m); new ObjectOutputStream(new FileOutputStream(new File(new 
	File(System. getProperty("user.dir")).getParent() + "/" + args[1] + "_local", "totalByte"))).writeObject(client.totalByte); 
	new ObjectOutputStream(new FileOutputStream(new File(new 
	File(System. getProperty("user.dir")).getParent() + "/" + args[1] + "_local", "numBlocks"))).writeObject(client.numBlocks); 
	
	FileWriter fwr = new FileWriter(new File(new File(System. getProperty("user.dir")).getParent() + "/" + args[1] + "_local", "results.txt"), true); 
	fwr.append( (int)(new File(new 
	File(System. getProperty("user.dir")).getParent() + args[1] + "_local", "m").length() 
	+ new File(new File(System. getProperty("user.dir")).getParent() + args[1] + "_local", "totalByte").length() + new File(new File(System. getProperty("user.dir")).getParent() + args[1] + 	"_local", "numBlocks").length() + 16*client.numBlocks) + " bytes."); 	
	fwr.close(); 
	} 
	else if (args[0].equals("integrity_Verify")){ 
	int numBlocks; 
	int[][] m = null; 
	int totalByte;
	int checkBits = 1;
	List<Integer> list = new ArrayList<Integer>(); 
	File f = new File(new File(System. getProperty("user.dir")).getParent() + args[1] + "_local", "incorr.txt"); 
	if (f.exists()) 	
	f.delete(); 
	m = (int[][]) new ObjectInputStream(new FileInputStream(new File(new 
	File(System. getProperty("user.dir")).getParent() + "/" + args[1] + "_local", "m"))).readObject(); totalByte = (int) new ObjectInputStream(new FileInputStream(new File(new 
	File(System. getProperty("user.dir")).getParent() + "/" + args[1] + "_local","totalByte"))).readObject(); 
	numBlocks = (int) new ObjectInputStream(new FileInputStream(new File(new File(System. getProperty("user.dir")).getParent() + "/" + args[1] + "_local", 	"numBlocks"))).readObject(); 
	for (int i=0; i<numBlocks; i++){ 
	ArrayList<Integer> numbers = new ArrayList<Integer>(); 
	for(int s = 0; s < m[i].length; s++){ 
	numbers.add(s); 
	}
	Collections. shuffle(numbers); 
	for(int t = 0; t < checkBits; t++){ 
	int bytesToSkip = (int) (totalByte + i*(k/4 + 32)); 
	boolean res = integrity_Verify(args[1], i, m[i][numbers.get(t)], n, k, bytesToSkip, numbers.get(t)); 
	if (res==false) list.add(i); }
	}
	File fstat = new File(new File(System. getProperty("user.dir")).getParent() + "/" +	args[1] + "_local", "results.txt");
	FileWriter fwr = new FileWriter(fstat, true); 
	} 
	if (args[0].equals("Data_corrupt")){ 
	File in = new File(new File(System. getProperty("user.dir")).getParent(), args[1]); 
	File renameIn = new File(new File(System. getProperty("user.dir")).getParent(), args[1] +".orig"); 
	if(renameIn.exists()){ 
	renameIn.delete(); 
	renameIn = new File(new File(System. getProperty("user.dir")).getParent(), args[1] + ".orig"); 
	} 
	in.renameTo(renameIn); 
	FileInputStream inStream = new FileInputStream(renameIn); 
	File out = new File(new File(System. getProperty("user.dir")).getParent(), "out"); 
	FileOutputStream outStream = new FileOutputStream(out); 
	byte[] bytes = new byte[inStream.available()]; 
	while (inStream.available() > 0){ 
	inStream.read(bytes); 
	outStream.write(bytes); 
	outStream.flush(); 
	} 
	outStream.close(); 
	inStream.close(); 
	RandomAccessFile file = new RandomAccessFile(out, "rw"); 
	int bytesToCorrupt = Integer. parseInt(args[2]); 
	for(int i = 0; i < bytesToCorrupt; i++){ 
	long offset = file.getFilePointer(); 
	byte b = (byte) file.read(); 
	for (int j = 0; j < 8; j++){ 
	b ^= 1 << j; 
	} 
	file.seek(offset); 
	file.write(b); 
	} 
	file.close(); 
	File fstat = new File(new File(System. getProperty("user.dir")).getParent() + "/" + args[1] + "_local", "results.txt"); 
	FileWriter stat = new FileWriter(fstat, true); 
	int blocksCor = (int)bytesToCorrupt/n + 1; 
	int totalByte = (int) new ObjectInputStream(new FileInputStream(new File(new 
	File(System. getProperty("user.dir")).getParent() + "/" + args[1] + "_local","totalByte"))).readObject(); 
	DecimalFormat df = new DecimalFormat("#.##"); 
	stat.write(	df.format((double)bytesToCorrupt*100/(double)totalByte) + "%."); 
	stat.close(); 
	in.delete(); 
	out.renameTo(new File(new File(System. getProperty("user.dir")).getParent(), args[1])); 
	} 
	} 
	} 
	
