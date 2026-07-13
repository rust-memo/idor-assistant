package com.adminsec.idor.model;

import java.util.List;

public record Assessment(int score, String priority, String endpointTemplate,
                         List<Reference> references, List<String> reasons) {}
