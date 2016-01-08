
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



public class Client { 


	 int[][][] meta; 

	 int totalByte; 

	 int numBlocks; 

	public Client(int[][][] meta, int totalByte, int numBlocks) { 

		this.meta = meta; 
		this.totalByte = totalByte; 
		this.numBlocks = numBlocks; 
	} 

	//-----------------------------------------------------------
	//«· Õﬁﬁ „‰ «·”·«„… 
	public static boolean Integrity_verify(String filename, int blockNum, int posInBlock, 	
			int n, int k, int bytesToSkip, int posInTable) 
					throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, 
					InvalidKeyException, IllegalBlockSizeException, BadPaddingException { 

		boolean res = false;
		
		Cloud_Server.metadata_Rertieve(filename, blockNum, posInBlock, n, bytesToSkip, k);
		int metaBit = Cloud_Server.metaBit; 

		String metaBlockEnc = Cloud_Server.enc_metaBlock; 

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
				byte[] original = cipher.doFinal(b); 
				byte metaB = original[posInTable/8]; 
				int bit = posInTable%8; 
				int c = metaB & (1 << bit); 
				if(c != 0){ 
					c=1; 
				} 
				if (metaBit == c){ 
					res = true; 
				} 
	
			}
			catch(Exception e){ 
			
				System. exit(0); 
			}
		}
		catch(Exception e){ 

			System. exit(0); 
		}
		return res; 
	}
	public static Client config (String fileName, int n, int k) 

			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, 

			InvalidKeyException, IllegalBlockSizeException, BadPaddingException{ 

		File file = new File(new File(System. getProperty("user.dir")).getParent(), fileName); 

		FileInputStream inStream = new FileInputStream(file); 
		File dir = new File(new File(System. getProperty("user.dir")).getParent(), fileName + "_local"); 



		if (dir.exists()){ 

			if (dir.isDirectory()) { 

				File[] children = dir.listFiles(); 

				for (int i=0; i<children.length; i++) { 

					children[i].delete(); 
				}
			}
		} 	


		dir.mkdir(); 
		File fileEnc = new File(new File(System. getProperty("user.dir")).getParent(), fileName + "_local/"+ "res"); 

		FileWriter outStreamEnc = new FileWriter(fileEnc, true); 

		File f = new File(new File(System. getProperty("user.dir")).getParent(), fileName + "_local/results.txt"); 

		FileWriter stat = new FileWriter(f); 



		long totalByte = inStream.available(); 



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

		Client client = new Client(m, (int)totalByte, numBlocks); 

		return client; 
	} 



	
} 

