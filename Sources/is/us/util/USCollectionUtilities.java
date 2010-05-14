package is.us.util;

import java.lang.reflect.Array;
import java.util.*;

/**
 * Various utility methods for collections.
 * 
 * @author Hugi Thordarson
 */

public class USCollectionUtilities {

	/**
	 * @param list The list to use
	 * @return A human readable version of the list.
	 */
	public static String humanReadableList( List<?> list ) {
		StringBuilder b = new StringBuilder();

		for( int i = 0; i < list.size(); i++ ) {
			Object o = list.get( i );

			b.append( o );

			if( i == list.size() - 2 ) {
				b.append( " og " );
			}
			else if( i < list.size() - 2 ) {
				b.append( ", " );
			}

		}

		return b.toString();
	}

	/**
	 * Wrapper function to join collections.
	 */
	public static String join( Collection<? extends Object> collection, String separator ) {

		if( collection == null ) {
			return null;
		}

		return join( collection.toArray(), separator );
	}

	/**
	 * Joins an array, using the delimiter, into a string.
	 */
	public static String join( Object[] collection, String separator ) {

		if( collection == null ) {
			return null;
		}

		StringBuffer retString = new StringBuffer();

		for( int i = 0; i < collection.length; i++ ) {
			if( (i > 0) && (separator != null) ) {
				retString.append( separator );
			}
			retString.append( String.valueOf( collection[i] ) );
		}

		return retString.toString();
	}

	/**
	 * Searches for an element in an unsorted array
	 * 
	 * @param arr array to search through
	 * @param elementToFind element to find
	 * @return index of element in the array, if element is not found then -1
	 */
	public static <T> int searchUnsorted( T[] arr, T elementToFind ) {
		if( (arr == null) || (elementToFind == null) || (arr.length < 1) ) {
			return -1;
		}
		for( int i = 0; i < arr.length; i++ ) {
			if( arr[i].equals( elementToFind ) ) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Resizes a array.
	 * 
	 * @param arr array to resize
	 * @param newSize new array size
	 * @return resized array
	 * @exception  IndexOutOfBoundsException  if copying would cause
	 *               access of data outside array bounds.
	 * @exception  ArrayStoreException  if an element in the <code>src</code>
	 *               array could not be stored into the <code>dest</code> array
	 *               because of a type mismatch.
	 * @exception  NullPointerException if either <code>src</code> or
	 *               <code>dest</code> is <code>null</code>.
	 */
	@SuppressWarnings( "unchecked" )
	public static <T> T[] resize( T[] arr, int newSize ) {
		if( newSize < 1 ) {
			return (T[])Array.newInstance( arr.getClass().getComponentType(), 0 );
		}
		T[] newArr = (T[])Array.newInstance( arr.getClass().getComponentType(), newSize );
		System.arraycopy( arr, 0, newArr, 0, arr.length );
		return newArr;
	}
}
