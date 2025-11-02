---
layout: page
title: Blog Archive
---

<style>
.tag-section {
  margin-bottom: 2.5em;
  padding: 1.5em;
  background-color: var(--header-bg);
  border-radius: 8px;
  border: 1px solid var(--border-color);
  transition: all 0.3s ease;
}

.tag-section:target {
  box-shadow: 0 0 0 3px var(--link-color);
  border-color: var(--link-color);
}

.tag-header {
  display: inline-block;
  padding: 0.4em 1em;
  background-color: var(--tag-hover-bg);
  color: var(--tag-hover-text);
  border-radius: 12px;
  font-weight: 600;
  margin-bottom: 1em;
}

.tag-section ul {
  list-style: none;
  padding-left: 0;
}

.tag-section li {
  padding: 0.5em 0;
  border-bottom: 1px solid var(--border-color);
  transition: background-color 0.2s ease;
}

.tag-section li:last-child {
  border-bottom: none;
}

.tag-section li:hover {
  background-color: var(--nav-hover-bg);
  padding-left: 0.5em;
}

.tag-section a {
  color: var(--link-color);
  text-decoration: none;
  display: block;
}

.tag-section a:hover {
  color: var(--link-hover-color);
}
</style>

{% for tag in site.tags %}
  <div class="tag-section" id="{{ tag[0] | slugify }}">
    <h3 class="tag-header">{{ tag[0] }}</h3>
    <ul>
      {% for post in tag[1] %}
        <li><a href="{{ post.url }}">{{ post.date | date: "%B %Y" }} - {{ post.title }}</a></li>
      {% endfor %}
    </ul>
  </div>
{% endfor %}