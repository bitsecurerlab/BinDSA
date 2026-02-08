
public class Pair<K, V> {
	private K element0;
	private V element1;

	public Pair(K element0, V element1) {
		this.element0 = element0;
		this.element1 = element1;
	}

	public K getK() {
		return element0;
	}

	public V getV() {
		return element1;
	}

	public void setV(V v) {
		this.element1 = v;
	}

	public String toString() {
		return element0.toString() + "_" + element1.toString();
	}
	
	public int hashCode() {
		return element0.hashCode() + element1.hashCode();
	}
}