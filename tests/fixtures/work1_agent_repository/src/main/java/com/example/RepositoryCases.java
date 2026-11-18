package com.example;

@interface Marker {}
@interface Named { String value(); }

interface Worker<T> {
    T convert(T value);
}
@Marker
public class RepositoryCases<T> implements Worker<T> {
    // Comment braces must not change ownership: { } {{
    private final String template = "literal braces { are not blocks }";
    private java.util.Map<String, java.util.List<T>> values;
    private String name;

    public RepositoryCases() {
        this("default");
    }

    public RepositoryCases(String name) {
        this.name = name;
        helper(name);
    }

    @Override
    public T convert(T value) {
        return value;
    }

    public <R extends Number> R process(
        @Named(value = "items") java.util.List<T> items,
        R fallback
    ) {
        service.load(items);
        helper(fallback.toString());
        return fallback;
    }

    public void process(String value) {
        sink(value);
    }

    class Nested {
        private int count;

        Nested(int count) {
            this.count = count;
            nestedCall();
        }
    }
}
