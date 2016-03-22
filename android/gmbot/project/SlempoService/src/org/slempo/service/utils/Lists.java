package org.slempo.service.utils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;

public class Lists {
	public static <T> ArrayList<T> newArrayList() {
		return new ArrayList();
	}

	public static <T> ArrayList<T> newArrayList(int paramInt) {
		return new ArrayList(paramInt);
	}

	public static <T> ArrayList<T> newArrayList(Collection<T> paramCollection) {
		if (paramCollection != null)
			;
		for (int i = paramCollection.size();; i = 0) {
			ArrayList localArrayList = newArrayList(i);
			localArrayList.addAll(paramCollection);
			return localArrayList;
		}
	}

	public static <T> ArrayList<T> newArrayList(T[] paramArrayOfT) {
		ArrayList localArrayList = new ArrayList(paramArrayOfT.length);
		int i = paramArrayOfT.length;
		for (int j = 0; j < i; j++)
			localArrayList.add(paramArrayOfT[j]);
		return localArrayList;
	}

	public static <T> LinkedList<T> newLinkedList() {
		return new LinkedList();
	}
}
