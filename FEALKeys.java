import java.io.*;
import java.util.ArrayList;

public class FEALKeys {

	static public class KeyOptions {

		public static int keyZero = -1, keyOne = -1, keyTwo = -1, keyThree = -1, keyFour = -1, keyFive = -1;

		KeyOptions (int k0, int k1, int k2, int k3, int k4, int k5 ) {
			keyZero = k0;
			keyOne = k1;
			keyTwo = k2;
			keyThree = k3;
			keyFour = k4;
			keyFive = k5;
		}

	}

	private static int L0, R0, L4, R4;
	static final int PAIRS_LENGTH = 200;
	private static String [] cipherText = new String[ PAIRS_LENGTH ];

	private static String [] plainText = new String[ PAIRS_LENGTH ];
	private static ArrayList <KeyOptions> keys = new ArrayList<KeyOptions>();
	private static ArrayList <Integer> key0 = new ArrayList<Integer>();
	private static ArrayList <Integer> key1 = new ArrayList<Integer>();

	private static void dividePairs ( int index ) {
		L0 = pack( plainText[ index ], 0 );
		R0 = pack( plainText[ index ], 4 );
		L4 = pack( cipherText[ index ], 0 );
		R4 = pack( cipherText[ index ], 4 );
	}

	private static int pack ( String text, int index ) {

		byte [] b = new byte[ 8 ];

		for ( int i = 0, j = 0; i < b.length; i++, j += 2 ) {
			b[ i ] = ( byte )( Integer.parseInt( text.substring( j, j + 2 ),16)&255);
		} 

		return FEAL.pack( b, index);

	}

	// return whether bit is 1 or 0
	private static int returnBit ( int num, int bit )  {

		int pos = 1;
		pos <<= 31 - bit;

		if ( ( num & pos ) != 0 ) {
			return 1;
		} else {
			return 0;
		}

	}

	// organise bits into 10..15 & 18..23
	private static int inner12Bits ( int key ) {
		return ( ( key & ( 0x3f << 6 ) ) << 10 ) | ( ( key & 0x3F ) << 8 );
	}

	// organise bits into 0..9 & 16..17 & 24..31
	// finally managed to fix this - then all of them fixed
	private static int outer20Bits ( int key, int innerBits ) {
		// place inner bits in key
		int a0 = ( ( ( key & 0xF ) >> 2 ) << 6 ) + ( ( innerBits >> 16 ) & 0xFF );
		int a1 = ( ( key & 0x3 ) << 6 ) + ( ( innerBits >> 8 ) & 0xFF );

		// organise bytes
		int b0 = ( key >> 12 ) & 0xFF;
		int b3 = ( key >> 4 ) & 0xFF;

		int b1 = b0^a0;
		int b2 = b3^a1;

		return (b0 << 24)  + (b1 << 16) + (b2 << 8) + b3;
	}

	// calculate the inner const ( from video )
	// a = S5, S13, S21( L0 XOR R0 XOR L4 ) XOR S15( L0 XOR L4 XOR R4 ) XOR S15( F ( L0 XOR R0 XOR K0 ) )
	private static int calcInnerConstK0 ( int key ) {

		// a = S5, 13, 21( L0 XOR R0 XOR L4 )
		int a1 =  returnBit( L0 ^ R0 ^ L4, 5 ) ^ returnBit( L0 ^ R0 ^ L4, 13 ) ^ returnBit( L0 ^ R0 ^ L4, 21 );

		// S15( L0 XOR L4 XOR R4 )
		int a2 = returnBit( L0 ^ L4 ^ R4, 15 );

		// S15( F ( L0 XOR R0 XOR K0 ) )
		int a3 = returnBit( FEAL.f( L0 ^ R0 ^ key ), 15 );

		return a1 ^ a2 ^ a3; 

	}

	// calc inner bits possibilities 10..15 & 18..23 
	private static void innerValuesK0 () {

		int j = 0;
		boolean moveOn = false;
		int key = 0;

		// optimised version of the original function - move on if its not equal to the first result
		for ( int i = 0; i < Math.pow(2, 12); i++ ) {

			key = inner12Bits( i );
			dividePairs( 0 );
			j = calcInnerConstK0( key );
			int k = 0;
			for ( k = 1; k < PAIRS_LENGTH; k++ ) {

				dividePairs( k );

				if ( j != calcInnerConstK0( key ) ) {

					moveOn = true;
					k = PAIRS_LENGTH;

				}

			}

			if ( !moveOn ) {
				System.out.println( "SUCCESS Inner Values K0: " + Integer.toHexString( key ) );
				outerValuesK0( key );
			} else {
				moveOn = false;
			}

		}

	}

	// calculate the outer const 
	private static int calcOuterConstK0 ( int key ) {

		// S13(L0 ⊕ R0 ⊕ L4)
		int a1 = returnBit( L0 ^ R0 ^ L4 , 13 );

		// S7,15,23,31(L0 ⊕ L4 ⊕ R4)
		int a2 = returnBit( L0 ^ L4 ^ R4, 7 ) ^ returnBit( L0 ^ L4 ^ R4, 15 ) ^ returnBit( L0 ^ L4 ^ R4, 23 ) ^ returnBit( L0 ^ L4 ^ R4, 31 );

		// S7,15,23,31 F(L0 ⊕ R0 ⊕ K0)
		int y0 = FEAL.f( L0 ^ R0 ^ key );
		int a3 = returnBit( y0, 7 ) ^ returnBit( y0, 15 ) ^ returnBit( y0, 23 ) ^ returnBit( y0, 31 );

		return a1^a2^a3;


	}

	private static void outerValuesK0 ( int keyInnerBits ) {
		int j = 0;
		boolean moveOn = false;
		int key = 0;

		// optimised version of the original function - move on if its not equal to the first result
		for ( int i = 0; i < Math.pow( 2, 20 ); i++ ) {
			key = outer20Bits( i, keyInnerBits );
			dividePairs( 0 );
			j = calcOuterConstK0( key );

			int k = 0;
			for ( k = 1; k < PAIRS_LENGTH; k++ ) {

				dividePairs( k );

				if ( j != calcOuterConstK0( key ) ) {
					moveOn = true;
					k = PAIRS_LENGTH;


				}

			}

			if ( !moveOn ) {
				//System.out.println( "SUCCESS K0: " + Integer.toHexString( key ) );
				keyOne( key );
			} else {
				moveOn = false;

			}
		}
	}

	private static void keyZero () {
		System.out.println( "Begin attack on key zero....." );
		innerValuesK0();
	}

	// calc inner bits possibilities 10..15 & 18..23 
	private static void innerValuesK1 ( int k0 ) {

		int j = 0;
		boolean moveOn = false;
		int key = 0;

		// optimised function again
		for ( int i = 0; i < Math.pow( 2, 12 ); i++ ) {

			key = inner12Bits( i );
			dividePairs( 0 );
			j = calcInnerConstK1( key, k0 );

			int k = 0;
			for ( k = 1; k < PAIRS_LENGTH; k++ ) {

				dividePairs( k );

				if ( j != calcInnerConstK1( key, k0 ) ) {
					moveOn = true;
					k = PAIRS_LENGTH;

				}

			}

			if ( !moveOn ) {
				outerValuesK1( key, k0 );
			} else {
				moveOn = false;
			} 

		}


	}

	// S5,13,21(L0 ⊕ L4 ⊕ R4) ⊕ S15 F(L0 ⊕ F(L0 ⊕ R0 ⊕ K0) ⊕ K1)
	private static int calcInnerConstK1 ( int k1, int k0 ) {

		// a = S5, 13, 21( L0 XOR R0 XOR L4 )
		int a1 =  returnBit( L0 ^ L4 ^ R4, 5 ) ^ returnBit( L0 ^ L4 ^ R4, 13 ) ^ returnBit( L0 ^ L4 ^ R4, 21 );

		int y = FEAL.f( L0 ^ R0 ^ k0 );

		// S15( F ( L0 XOR R0 XOR K0 ) )
		int a3 = returnBit( FEAL.f( L0 ^ y ^ k1 ), 15 );

		return a1 ^ a3; 

	}

	private static int calcOuterConstK1 ( int k1, int k0 ) {

		// S13(L0 ⊕ L4 ⊕ R4)
		int a1 = returnBit( L0 ^ L4 ^ R4 , 13 );

		// S7,15,23,31 F(L0 ⊕ y ⊕ K0)
		int y0 = FEAL.f( L0 ^ R0 ^ k0 );
		int y1 = FEAL.f( L0 ^ y0 ^ k1 );

		int a3 = returnBit( y1, 7 ) ^ returnBit( y1, 15 ) ^ returnBit( y1, 23 ) ^ returnBit( y1, 31 );

		return a1 ^ a3;

	}

	private static void outerValuesK1 ( int keyInnerBits, int key0 ) {

		int j = 0;
		boolean moveOn = false;
		int key = 0;

		// optimised version of the original function - move on if its not equal to the first result
		for ( int i = 0; i < Math.pow( 2, 20 ); i++ ) {

			key = outer20Bits( i, keyInnerBits );
			dividePairs( 0 );
			j = calcOuterConstK1( key, key0 );

			int k = 0;
			for ( k = 1; k < PAIRS_LENGTH; k++ ) {

				dividePairs( k );

				if ( j != calcOuterConstK1( key, key0 ) ) {
					moveOn = true;
					k = PAIRS_LENGTH;

				}

			}

			if ( !moveOn ) {
				keyTwo( key0, key );

			} else {
				moveOn = false;

			}

		}

	}

	private static void keyOne ( int k0 ) {
		innerValuesK1( k0 );
	}

	// calc inner bits possibilities 10..15 & 18..23 
	private static void innerValuesK2 ( int k0, int k1 ) {

		int j = 0;
		boolean moveOn = false;
		int key = 0;

		// optimised function again
		for ( int i = 0; i < Math.pow( 2, 12 ); i++ ) {

			key = inner12Bits( i );
			dividePairs( 0 );
			j = calcInnerConstK2( key, k0, k1 );

			int k = 0;
			for ( k = 1; k < PAIRS_LENGTH; k++ ) {

				dividePairs( k );

				if ( j != calcInnerConstK2( key, k0, k1 ) ) {
					moveOn = true;
					k = PAIRS_LENGTH;

				}

			}

			if ( !moveOn ) {
				outerValuesK2( key, k0, k1 );
			} else {
				moveOn = false;
			} 

		}


	}


	private static int calcInnerConstK2 ( int k2, int k0, int k1 ) {

        int a1 = returnBit( L0 ^ R0 ^ L4, 5 ) ^ returnBit( L0 ^ R0 ^ L4, 13 ) ^ returnBit( L0 ^ R0 ^ L4, 21 );

        int y0 = FEAL.f( L0 ^ R0 ^ k0 );
        int y1 = FEAL.f( L0 ^ y0 ^ k1 );
        int a2 = returnBit( FEAL.f( L0 ^ R0 ^ y1 ^ k2), 15 );

        return a1 ^ a2;

	}

	private static int calcOuterConstK2_2 ( int k2, int k0, int k1 ) {

		int a1 = returnBit( L0 ^ R0 ^ L4 , 23 ) ^ returnBit( L0 ^ R0 ^ L4 , 29 );
		
		int y0 = FEAL.f( L0 ^ R0 ^ k0 );
		int y1 = FEAL.f( L0 ^ y0 ^ k1 );

		int a3 = returnBit( FEAL.f( L0 ^ R0 ^ y1 ^ k2 ), 31 );

		return a1 ^ a3;

	}
	
	private static int calcOuterConstK2 ( int k2, int k0, int k1 ) {

		// S13(L0 ⊕ L4 ⊕ R4)
		int a1 = returnBit( L0 ^ R0 ^ L4 , 13 );

		// S7,15,23,31 F(L0 ⊕ y ⊕ K0)
		int y0 = FEAL.f( L0 ^ R0 ^ k0 );
		int y1 = FEAL.f( L0 ^ y0 ^ k1 );

		int a3 = returnBit( FEAL.f( L0 ^ R0 ^ y1 ^ k2), 7 ) ^ returnBit( FEAL.f( L0 ^ R0 ^ y1 ^ k2), 15 ) ^ returnBit( FEAL.f( L0 ^ R0 ^ y1 ^ k2), 23 ) ^ returnBit( FEAL.f( L0 ^ R0 ^ y1 ^ k2), 31 );

		return a1 ^ a3;

	}

	
	private static void outerValuesK2 ( int keyInnerBits, int key0, int K1 ) {

		int j = 0;
		int j2 = 0;
		boolean moveOn = false;
		int key = 0;

		// optimised version of the original function - move on if its not equal to the first result
		for ( int i = 0; i < Math.pow( 2, 20 ); i++ ) {

			key = outer20Bits( i, keyInnerBits );
			dividePairs( 0 );
			j = calcOuterConstK2( key, key0, K1 );
			j2 = calcOuterConstK2_2( key, key0, K1 );

			int k = 0;
			for ( k = 1; k < PAIRS_LENGTH; k++ ) {

				dividePairs( k );

				if ( j != calcOuterConstK2( key, key0, K1 ) || j2 != calcOuterConstK2( key, key0, K1 ) ) {
					moveOn = true;
					k = PAIRS_LENGTH;

				}

			}

			if ( !moveOn ) {
				System.out.println( "SUCCESS  K2: " + Integer.toHexString(key));
				// SkeyThree( key0, K1, key );
				key1.add( key );
			} else {
				moveOn = false;

			}

		}

	}

	private static void keyTwo ( int k0, int k1 ) {
		innerValuesK2( k0, k1 );
	}

	// calc inner bits possibilities 10..15 & 18..23 
	private static void innerValuesK3 ( int k0, int k1, int k2 ) {

		int j = 0;
		boolean moveOn = false;
		int key = 0;

		// optimised function again
		for ( int i = 0; i < Math.pow( 2, 12 ); i++ ) {

			key = inner12Bits( i );
			dividePairs( 0 );
			j = calcInnerConstK3( key, k0, k1, k2 );

			int k = 0;
			for ( k = 1; k < PAIRS_LENGTH; k++ ) {

				dividePairs( k );

				if ( j != calcInnerConstK3( key, k0, k1, k2 ) ) {
					moveOn = true;
					k = PAIRS_LENGTH;

				}

			}

			if ( !moveOn ) {
				//System.out.println( "Hola");
				outerValuesK3( key, k0, k1, k2 );
			} else {
				moveOn = false;
			} 

		}


	}


	private static int calcInnerConstK3 ( int k3, int k0, int k1, int k2 ) {

        int a1 = returnBit( L0 ^ R4 ^ L4, 5 ) ^ returnBit( L0 ^ R4 ^ L4, 13 ) ^ returnBit( L0 ^ R4 ^ L4, 21 );

        int a2 = returnBit( L0 ^ R0 ^ L4, 15 );
        
        int y0 = FEAL.f( L0 ^ R0 ^ k0 );
        int y1 = FEAL.f( L0 ^ y0 ^ k1 );
        int y2 = FEAL.f( L0 ^ R0 ^ y1 ^ k2 );
        int a3 = returnBit( FEAL.f( L0 ^ y2 ^ y0 ^ k3), 15 );

        return a1 ^ a2 ^ a3;

	}

	private static int calcOuterConstK3 ( int k3, int k0, int k1, int k2 ) {

		int a1 = returnBit( L0 ^ R4 ^ L4 , 13 );

		int a2 = returnBit( L0 ^ R0 ^ L4, 7 ) ^ returnBit( L0 ^ R0 ^ L4, 15 ) ^ returnBit( L0 ^ R0 ^ L4, 23 ) ^ returnBit( L0 ^ R0 ^ L4, 31 );

		
		int y0 = FEAL.f( L0 ^ R0 ^ k0 );
		int y1 = FEAL.f( L0 ^ y0 ^ k1 );
		int y2 = FEAL.f( L0 ^ R0 ^ y1 ^ k2 );

		int a3 = returnBit( FEAL.f( L0 ^ y0 ^ y2 ^ k3 ), 7 ) ^ returnBit( FEAL.f( L0 ^ y0 ^ y2 ^ k3 ), 15 ) ^ returnBit( FEAL.f( L0 ^ y2 ^ y0 ^ k3 ), 23 ) ^ returnBit( FEAL.f( L0 ^ y2 ^ y0 ^ k3 ), 31 );

		return a1 ^ a2 ^ a3;

	}
	
	private static int calcOuterConstK3_2 ( int k3, int k0, int k1, int k2 ) {

		int a1 = returnBit( L0 ^ R4 ^ L4 , 23 ) ^ returnBit( L0 ^ R4 ^ L4 , 29 );

		int a2 = returnBit( L0 ^ R0 ^ L4, 31 );
		
		int y0 = FEAL.f( L0 ^ R0 ^ k0 );
		int y1 = FEAL.f( L0 ^ y0 ^ k1 );
		int y2 = FEAL.f( L0 ^ R0 ^ y1 ^ k2 );

		int a3 = returnBit( FEAL.f( L0 ^ y0 ^ y2 ^ k3 ), 31 );

		return a1 ^ a2 ^ a3;

	}

	
	private static void outerValuesK3 ( int keyInnerBits, int key0, int K1, int k2 ) {

		int j = 0;
		int j2 = 0;
		boolean moveOn = false;
		int key = 0;

		// optimised version of the original function - move on if its not equal to the first result
		for ( int i = 0; i < Math.pow( 2, 20 ); i++ ) {

			key = outer20Bits( i, keyInnerBits );
			dividePairs( 0 );
			j = calcOuterConstK3( key, key0, K1, k2 );
			j2 = calcOuterConstK3_2( key, key0, K1, k2 );

			int k = 0;
			for ( k = 1; k < PAIRS_LENGTH; k++ ) {

				dividePairs( k );

				if ( j != calcOuterConstK3( key, key0, K1, k2 ) || j2 != calcOuterConstK3_2( key, key0, K1, k2 ) ) {
					moveOn = true;
					k = PAIRS_LENGTH;

				}

			}

			if ( !moveOn ) {
				System.out.println( "SUCCESS  K3: " + Integer.toHexString(key));
				key1.add( key );

			} else {
				moveOn = false;

			}

		}

	}

	private static void keyThree ( int k0, int k1, int k2 ) {
		innerValuesK3( k0, k1, k2 );
	}

	private static void evaluatePossibilities ( int k0, int k1, int k2, int k3 ) {

		// from Future Learn diagram
		int y0 = FEAL.f( L0 ^ R0 ^ k0 );
		int y1 = FEAL.f( L0 ^ y0 ^ k1 );
		int y2 = FEAL.f( L0 ^ R0 ^ y1 ^ k2 );
		int y3 = FEAL.f( L0 ^ y2 ^ k3 );

		int k4 = L0 ^ R0 ^ y1 ^ y3 ^ L4;
		int k5 = R0 ^ y1 ^ y3 ^ y0 ^ y2 ^ R4;

		int key [] = { k0, k1, k2, k3, k4, k5 };

		int i = 0;
		// test keys against pairs
		for ( i = 0; i < PAIRS_LENGTH; i++ ) {

			byte [] b = new byte[ 8 ];

			for ( int l = 0, j = 0; i < b.length; l++, j += 2 ) {
				b[ l ] = ( byte )( Integer.parseInt( plainText[ i ].substring( j, j + 2 ),16)&255);
			}  

			FEAL.encrypt( b, key );
			String current = "";
			current += b[ 0 ] + b[ 1 ] + b[ 2 ] + b[ 3 ] + b[ 4 ] + b[ 5 ] + b[ 6 ] + b[ 7 ];

			if ( !cipherText[ i ].equals( current ) ) {
				break;
			}

		}

		if ( i == PAIRS_LENGTH ) {
			KeyOptions current = new KeyOptions( k0, k1, k2, k3, k4, k4 );
			keys.add( current );
			System.out.println( "Key zero:    0x" + Integer.toHexString( k0 ) );
			System.out.println( "Key one:     0x" + Integer.toHexString( k1 ) );
			System.out.println( "Key two:     0x" + Integer.toHexString( k2 ) );
			System.out.println( "Key three:   0x" + Integer.toHexString( k3 ) );
			System.out.println( "Key four:    0x" + Integer.toHexString( k4 ) );
			System.out.println( "Key five:    0x" + Integer.toHexString( k5 ) );
		}

	}


	// populate the arrays with all of the pairs
	private static void populatePairs () throws IOException {

		FileReader fr = new FileReader("known.txt"); 
		BufferedReader br = new BufferedReader(fr);

		String currentLine = br.readLine();
		int count = 0; 

		while( currentLine != null && count < PAIRS_LENGTH ) {

			// cipher text/plain text always starts after 12 bytes
			plainText[ count ] = currentLine.substring( 12 );

			currentLine = br.readLine();

			cipherText[ count ] = currentLine.substring( 12 );

			count++;
			br.readLine();
			currentLine = br.readLine();
		}

		br.close();

		System.out.println( "String pairs populated.");

	}


	public static void main(String[] args) throws IOException {

		System.out.println( "Populating string pairs......." );
		populatePairs();

		keyZero();
		System.out.println(key1.size());
		for ( int i = 0; i < 32; i++ ) {
			int bit = returnBit( key1.get( 0 ), i );
			int j = 0;
			for ( j = 1; j < key1.size(); j++ ) {
				if ( bit != returnBit( key1.get( j ), i ) ) break;
			}
			if ( j == key1.size() ) System.out.print(bit);
			else System.out.print("?");
		}

		System.out.println( "Number of matching key sets: " + keys.size() );		

	}

}