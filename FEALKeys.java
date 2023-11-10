import java.io.*;
import java.util.ArrayList;

public class FEALKeys {

	private static int L0, R0, L4, R4;
	static final int PAIRS_LENGTH = 200;
	private static String [] cipherText = new String[ PAIRS_LENGTH ];
	private static String [] plainText = new String[ PAIRS_LENGTH ];
	private static int keyZero = -1, keyOne = -1, keyTwo = -1, keyThree = -1, keyFour = -1, keyFive = -1;
	private static ArrayList <Integer> key0 = new ArrayList();

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
		pos <<= 31-bit;

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

	// calculate the inner const ( from video )
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
				System.out.println( "DONE INNER BITS Key0: " + Integer.toBinaryString( key ) );
				key0.add( key );
			} else {
				moveOn = false;
			}

		}

		if ( key0.size() == 0 ) {
			System.out.println( "FAILED INNER BITS ");
		}

	}

	// calculate the outer const 
	// a = S23, 29( L0 XOR R0 XOR L4 ) XOR S31( L0 XOR L4 XOR R4 ) XOR S31( F ( L0 XOR R0 XOR K0 ) )

	private static int calcOuterConstK0 ( int key ) {
		/*
		int a1 = returnBit( L0 ^ R0 ^ L4, 13 );

		int a2 = returnBit( L0 ^ L4 ^ R4, 7 ) ^ returnBit( L0 ^ L4 ^ R4, 15 ) ^ returnBit( L0 ^ L4 ^ R4, 23 ) ^ returnBit( L0 ^ L4 ^ R4, 31 );

		int y = FEAL.f( L0 ^ R0 ^ key );
		int a3 = returnBit( y, 7) ^ returnBit( y, 15) ^ returnBit( y, 23) ^ returnBit( y, 31);

		return a1 ^ a2 ^ a3;*/
		int a1 = returnBit( (L0 ^ R0 ^ L4 ), 23 ) ^ returnBit( (L0 ^ R0 ^ L4 ), 29 );

		int a2 = returnBit( (L0 ^ L4 ^ R4 ), 31 );

		int a3 = returnBit( FEAL.f (L0 ^ R0 ^ key ), 31 );

		return a1 ^ a2 ^ a3;

	}

	// organise bits into 0..9 & 16..17 & 24..31
	private static int outer20Bits ( int key ) {
		//return ( ( ( key >> 12 ) & 0xFF ) << 24 ) + ( ( ( key & 0xF ) >> 2 ) << 6 ) + ( ( key & 0x3 ) << 6 ) + ( ( key >> 4 ) & 0xFF );
		//return ( ( key & 0x300 ) << 6 ) + ( key & 0xFF );
		// return ( ( key & 0xFFC00 ) << 12 ) | ( ( key & 0x300 ) << 6 ) | ( key & 0xFF );
		/*
		int a0 = (((key & 0xF) >> 2) << 6) + ((tilda >> 16) & 0xFF);
        int a1 = ((key & 0x3) << 6) + ((tilda >> 8) & 0xFF);

        int b0 = (key >> 12) & 0xFF;
        int b3 = (key >> 4) & 0xFF;

        int b1 = b0^a0;
        int b2 = b3^a1;*/

		//return (b0 << 24)  + (b1 << 16) + (b2 << 8) + b3;
		return ( ( key & 0xFFC00 ) << 12 ) | ( ( key & 0x300 ) << 6 ) | ( key & 0xFF );

	}

	private static int outerValuesK0 () {

		int j = 0;

		boolean moveOn = false;
		int key = 0;
		int maxCount = 0;

		for ( int l = 0; l < key0.size(); l++ ) {
			
			key = 0;
			
			// optimised version of the original function - move on if its not equal to the first result
			for ( int i = 0; i < Math.pow( 2, 20 ); i++ ) {

				key = outer20Bits( i );
				key |= key0.get( l );
				dividePairs( 0 );
				j = calcOuterConstK0( key );

				int k = 0;
				for ( k = 1; k < PAIRS_LENGTH; k++ ) {

					dividePairs( k );

					if ( j != calcOuterConstK0( key ) ) {
						if ( maxCount < k ) maxCount = k;
						moveOn = true;
						//System.out.println( "hello " + Integer.toBinaryString( key ) + " and " + k );
						k = PAIRS_LENGTH;

					}

				}

				if ( !moveOn ) {
					System.out.println( "FOUND OUTER BITS Key0 " );
					return key;
				} else {
					moveOn = false;
				}

			}
		}

		System.out.println( "DONE OUTER BITS Key0: " + Integer.toHexString( key ) );
		System.out.println( "FAILED OUTER BITS" );
		return -1;

	}

	// a = S23, 29( L0 XOR R0 XOR L4 ) XOR S31( L0 XOR L4 XOR R4 ) XOR S31( F ( L0 XOR R0 XOR K0 ) )
	private static int keyZero () {
		System.out.println( "Begin attack on key zero....." );
		innerValuesK0();
		return outerValuesK0();
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

		keyZero = keyZero();
		System.out.println( "Key zero:  0x" + Integer.toHexString( keyZero ) );		

		if ( keyZero != -1 && keyOne != -1 && keyTwo != -1 && keyThree != -1 && keyFour != -1 && keyFive != -1 ) {

			System.out.println( "Key zero:  0x" + Integer.toHexString( keyZero ) );
			System.out.println( "Key one:   0x" + Integer.toHexString( keyOne ) );
			System.out.println( "Key two:   0x" + Integer.toHexString( keyTwo ) );
			System.out.println( "Key three: 0x" + Integer.toHexString( keyThree ) );
			System.out.println( "Key four:  0x" + Integer.toHexString( keyFour ) );
			System.out.println( "Key five:  0x" + Integer.toHexString( keyFive ) );

			System.out.println( "Attack finished" );

		} else {
			System.out.println( "ATTACK FAILED" );
		}	

	}

}